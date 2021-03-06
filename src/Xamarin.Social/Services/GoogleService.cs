using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xamarin.Auth;
using Xamarin.Utilities;

namespace Xamarin.Social.Services
{
	public class GoogleService : OAuth2Service
	{
		public GoogleService ()
			: base ("Google", "Google")
		{
			AuthorizeUrl = new Uri ("https://accounts.google.com/o/oauth2/auth");
			AccessTokenUrl = new Uri ("https://accounts.google.com/o/oauth2/token");
			Scope = "https://www.googleapis.com/auth/plus.login";
		}

		public override string [] Scopes {
			set {
				Scope = (value != null)
					? string.Join (" ", value)
					: null;
			}
		}

		protected override Task<string> GetUsernameAsync (IDictionary<string, string> accountProperties)
		{
			var request = base.CreateRequest ("GET",
				new Uri ("https://www.googleapis.com/plus/v1/people/me"),
				new Dictionary<string, string> {
					{ "fields", "url,id" }
				},
				new Account (string.Empty, accountProperties));

			return request.GetResponseAsync ().ContinueWith (reqTask => {
				var responseText = reqTask.Result.GetResponseText ();
				return WebEx.GetValueFromJson (responseText, "id");
			});
		}

		protected override Authenticator GetAuthenticator ()
		{
			return new GoogleAuthenticator (ClientId, ClientSecret, Scope, AuthorizeUrl, RedirectUrl, AccessTokenUrl, GetUsernameAsync);
		}

		public override Task<Account> ReauthorizeAsync (Account account)
		{
			var authenticator = (GoogleAuthenticator) GetAuthenticator ();

			return authenticator.RefreshAccessTokenAsync (account.Properties ["refresh_token"]).ContinueWith (t => {
				var props = new Dictionary<string, string> (account.Properties);
				props ["access_token"] = t.Result ["access_token"];
				return new Account (account.Username, props, account.Cookies);
			});
		}

		public override bool SupportsReauthorization {
			get {
				return true;
			}
		}

		public override Task VerifyAsync (Account account, CancellationToken token)
		{
			return CreateRequest ("GET",
				new Uri ("https://www.googleapis.com/plus/v1/people/me"),
				account
			).GetResponseAsync (token).ContinueWith (t => {
				if (!t.Result.GetResponseText ().Contains ("\"id\""))
					throw new SocialException ("Unrecognized Google response.");
			}, token);
		}

		public override bool SupportsVerification {
			get {
				return true;
			}
		}

		class GoogleAuthenticator : OAuth2Authenticator {
			private string clientId, clientSecret;

			public Task<IDictionary<string, string>> RefreshAccessTokenAsync (string refreshToken)
			{
				return RequestAccessTokenAsync (new Dictionary<string, string> {
					{ "grant_type", "refresh_token" },
					{ "client_id", clientId },
					{ "client_secret", clientSecret },
					{ "refresh_token", refreshToken }
				});
			}

			public GoogleAuthenticator (string clientId, string clientSecret, string scope, Uri authorizeUrl, Uri redirectUrl, Uri accessTokenUrl, GetUsernameAsyncFunc getUsernameAsync)
				: base (clientId, clientSecret, scope, authorizeUrl, redirectUrl, accessTokenUrl, getUsernameAsync)
			{
				this.clientId = clientId;
				this.clientSecret = clientSecret;
			}
		}
	}
}