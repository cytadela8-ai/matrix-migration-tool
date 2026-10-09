//! Native OAuth authorization-code/PKCE and legacy SSO. Only explicit unsupported OAuth
//! selects SSO; network, metadata and registration failures must remain visible.

use anyhow::{Context, Result, bail, ensure};
use matrix_sdk::{
    Client,
    authentication::oauth::{
        error::OAuthDiscoveryError,
        registration::{ApplicationType, ClientMetadata, Localized, OAuthGrantType},
    },
    reqwest::Url,
    ruma::{api::client::session::get_login_types::v3::LoginType, serde::Raw},
};
use zeroize::Zeroizing;

use crate::{callback::Callback, config::Account, prompt};

/// Authenticate through the server's browser UI; never solicit passwords or copied tokens.
pub async fn login(client: &Client, account: &Account) -> Result<()> {
    prompt::require_terminal()?;
    eprintln!("Browser login for {}", account.user_id);
    authorize(client, account, open_url).await
}

async fn authorize<F, Fut>(client: &Client, account: &Account, open: F) -> Result<()>
where
    F: FnOnce(Url) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    match client.oauth().server_metadata().await {
        Ok(_) => oauth_login(client, account, open).await,
        Err(OAuthDiscoveryError::NotSupported) => sso_login(client, open).await,
        Err(error) => Err(error).context("Discover OAuth login; check the homeserver connection"),
    }
}

async fn oauth_login<F, Fut>(client: &Client, account: &Account, open: F) -> Result<()>
where
    F: FnOnce(Url) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let callback = Callback::bind().await?;
    let homepage = Localized::new(Url::parse(env!("CARGO_PKG_REPOSITORY"))?, []);
    let metadata = ClientMetadata {
        client_name: Some(Localized::new("Matrix account migration".to_owned(), [])),
        ..ClientMetadata::new(
            ApplicationType::Native,
            vec![OAuthGrantType::AuthorizationCode { redirect_uris: vec![callback.url.clone()] }],
            homepage,
        )
    };
    let oauth = client.oauth();
    let auth = oauth
        .login(callback.url.clone(), None, Some(Raw::new(&metadata)?.into()), None)
        .user_id_hint(matrix_sdk::ruma::UserId::parse(&account.user_id)?.as_ref())
        .build()
        .await
        .context(
            "Register browser login; the authorization server may require administrator approval",
        )?;
    let result = async {
        open(auth.url.clone()).await?;
        let redirect = callback.receive(Some(auth.state.secret())).await?;
        oauth.finish_login(redirect.into()).await.context("Complete browser authorization")
    }
    .await;
    if result.is_err() {
        oauth.abort_login(&auth.state).await;
    }
    result
}

async fn sso_login<F, Fut>(client: &Client, open: F) -> Result<()>
where
    F: FnOnce(Url) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let types = client.matrix_auth().get_login_types().await.context("Discover SSO login")?;
    let mut supported = false;
    for flow in types.flows {
        if let LoginType::Sso(_) = flow {
            supported = true;
        }
    }
    ensure!(
        supported,
        "This homeserver supports neither OAuth nor SSO browser login. \
        Ask its administrator about browser authentication; init does not request account passwords"
    );
    let callback = Callback::bind().await?;
    let url = client.matrix_auth().get_sso_login_url(callback.url.as_str(), None).await?;
    open(Url::parse(&url)?).await?;
    let redirect = callback.receive(None).await?;
    let token = Zeroizing::new(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "loginToken")
            .context("SSO callback omitted its login token")?
            .1
            .into_owned(),
    );
    client
        .matrix_auth()
        .login_token(token.as_str())
        .initial_device_display_name("Matrix account migration")
        .request_refresh_token()
        .await
        .context("Complete SSO browser login")?;
    Ok(())
}

async fn open_url(url: Url) -> Result<()> {
    eprintln!("Opening your browser. If it does not open, use this login URL:\n{url}");
    let url = url.to_string();
    let result = tokio::task::spawn_blocking(move || open::that_detached(url)).await?;
    if let Err(error) = result {
        eprintln!("Could not launch a browser: {error}. Open the URL above on this computer.");
    }
    Ok(())
}

/// Check the authenticated identity and obtain explicit confirmation before saving a session.
pub async fn confirm_identity(client: &Client, account: &Account) -> Result<()> {
    check_identity(client, account)?;
    let user = client.user_id().context("Browser login returned no account identity")?;
    ensure!(
        prompt::confirm(&format!("Authenticated as {user}. Use this account?")).await?,
        "Account confirmation declined; no session was saved"
    );
    Ok(())
}

fn check_identity(client: &Client, account: &Account) -> Result<()> {
    let user = client.user_id().context("Browser login returned no account identity")?;
    if user.as_str() != account.user_id {
        bail!(
            "Browser logged in as {user}, expected {}. No session was saved. \
            Use the correct browser account and a fresh state directory if necessary",
            account.user_id
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "browser_tests.rs"]
mod tests;
