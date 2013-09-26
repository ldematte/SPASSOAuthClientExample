//
//SPASS OAuth Client Example
//Author: Lorenzo Dematté - Servizi ST 
//Copyright (C) 2013 Servizi ST Srl
//
//This file is part of the SPASS OAuth Client Example.
//
//SPASSOAuthClientExample is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.
//
//SPASSOAuthClientExample is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License v3
//along with SPASSOAuthClientExample.  If not, see <http://www.gnu.org/licenses/>.
//

using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Collections.Generic;

using ServiceStack.ServiceInterface;
using ServiceStack.Common;
using ServiceStack.Common.Web;
using ServiceStack.ServiceHost;
using ServiceStack.ServiceInterface.Auth;
using ServiceStack.OrmLite;
using ServiceStack.Text;
using ServiceStack.Text.Json;

using DotNetOpenAuth.Configuration;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth;
using DotNetOpenAuth.OAuth.ChannelElements;
using DotNetOpenAuth.OAuth.Messages;


namespace SPASSOAuthClientExample
{
	// DTOs for UserInfo request and response
	[Authenticate]
	[Route("/user-info", "GET")]
	public class UserInfoRequest: IReturn<UserInfo> { }

	public class UserInfo 
	{
		public string Name { get; set; }
		public bool Associated {
			get;
			set;
		}
		public string AccessToken {
			get;
			set;
		}
		public string TicketNumber {
			get;
			set;
		}
	}

	public class UserInfoRequestService : AppServiceBase { 

		// When  information about a User is requested, we answer with:
		// Base user information (Display name)
		// Information about the associated card IF any (must already have requested an access token and
		// used it to retrive the card(s) information)
		public object Any(UserInfoRequest request) { 
			var session = this.UserSession;
			if (!session.IsAuthenticated)
				return new HttpResult() { StatusCode = HttpStatusCode.Unauthorized };

			var associated = session.ProviderOAuthAccess.Exists (item => item.Provider == SiiOAuthProviderInfo.Name);
			String accessToken = null;
			String ticketNumber = null;

			if (associated) {
				var oauthInfo = session.ProviderOAuthAccess.Find (item => item.Provider == SiiOAuthProviderInfo.Name);
				accessToken = oauthInfo.AccessToken;
				ticketNumber = oauthInfo.Items.GetValueOrDefault ("SiiTicketNumber");
			}

			return new UserInfo { 
				Name = session.DisplayName,
				Associated = associated,
				AccessToken = accessToken,
				TicketNumber = ticketNumber
			};
		}
	}

	// Bogus HttpRequestCreator.
	// We only need it to work around a Mono bug 
	// See http://stackoverflow.com/questions/17657145/troubles-using-webrequest-in-mono 
	// for details
	class MyHttpRequestCreator : IWebRequestCreate
	{
		internal MyHttpRequestCreator ()
		{
		}

		public WebRequest Create (Uri uri)
		{
			throw new NotImplementedException ();
		}
	}


	[Authenticate]
	[Route("/sii-auth-request")]
	public class SiiOAuthRequest { }

	// Request access to the user info on our database
	// We have an OAuth provider, so we need to proceed with a standard OAuth request:
	// request token -(with callback)-> redirection to sii.bz.it for authentication ->
	// callback -> ... (see SiiOAuthCallbackService)
	public class SiiOAuthRequestService : ServiceStack.ServiceInterface.Service { 

		public object Any(SiiOAuthRequest request) { 
			var session = this.GetSession();
			if (!session.IsAuthenticated)
				return new HttpResult() { StatusCode = HttpStatusCode.Unauthorized };

			try {
				var serviceProvider = SiiOAuthProviderInfo.GetServiceDescription();
				var consumer = new WebConsumer(serviceProvider, this.TryResolve<IConsumerTokenManager>());

				// Url to redirect to
				var callback = new Uri(SiiOAuthProviderInfo.CALLBACK_URL);

				// HACK
				// Registering a bogus prefix seems to "wake up" the factory
				// Remove this is you run it under .NET
				// (it will do no harm, since longer prefixes are matched first, so http and https will
				// always wind, but still is a ugly hack)
				bool res = System.Net.WebRequest.RegisterPrefix ("htt", new MyHttpRequestCreator ());
				Debug.Assert (res == false);

				// request access
				var authRequest = consumer.PrepareRequestUserAuthorization(callback, null, null);
				return consumer.Channel.PrepareResponse(authRequest).AsHttpResult ();
			}
			catch (ProtocolException) {
				var result = new HttpResult ();

				result.StatusCode = HttpStatusCode.Redirect;
				result.Headers.Add(HttpHeaders.Location, new Uri(this.Request.UrlReferrer, "#/invalid-server-response").AbsoluteUri);
				return result; 
			}
			catch (Exception) {
				var result = new HttpResult ();

				result.StatusCode = HttpStatusCode.Redirect;
				result.Headers.Add(HttpHeaders.Location, new Uri(this.Request.UrlReferrer, "#/error").AbsoluteUri);
				return result; 
			}
		}
	}

	[Route("/sii-auth-callback")]
	public class SiiOAuthCallback { }

	// NOTE! This is a callback, it cannot have a response!
	// (callback) ... -> upgrade to access token -> use the token to get card info 
	// -> store token and card info in user profile
	public class SiiOAuthCallbackService: AppServiceBase { 

		public object Any(SiiOAuthCallback r) { 

			var session = this.UserSession;
			if (!session.IsAuthenticated)
				return new HttpResult () { StatusCode = HttpStatusCode.Unauthorized };

			var result = new HttpResult ();
			result.StatusCode = HttpStatusCode.Redirect;

			try {
				// Process result from the service provider
				var serviceProvider = SiiOAuthProviderInfo.GetServiceDescription ();
				var consumer = new WebConsumer (serviceProvider, this.TryResolve<IConsumerTokenManager>());
				var accessTokenResponse = consumer.ProcessUserAuthorization ();

				// If we didn't have an access token response, this wasn't called by the service provider
				if (accessTokenResponse == null)
					return new HttpResult () { StatusCode = HttpStatusCode.Unauthorized };

				// Extract the access token
				string accessToken = accessTokenResponse.AccessToken;

				// Retrieve the user's card information
				var getURL = SiiOAuthProviderInfo.API_URL + "/cardids.php";
				var endpoint = new MessageReceivingEndpoint (getURL, HttpDeliveryMethods.GetRequest);
				var request = consumer.PrepareAuthorizedRequest (endpoint, accessToken);

				string responseBody;
				try {
					var response = request.GetResponse();
					using (var reader =  new StreamReader(response.GetResponseStream())) {
						responseBody = reader.ReadToEnd ();
					}

					if (response.IsErrorResponse()) {
						result.Headers.Add(HttpHeaders.Location, new Uri(this.Request.UrlReferrer, "#/error").AbsoluteUri);
						return result; 
					}

				}
				catch (WebException ex) {
					result.Headers.Add(HttpHeaders.Location, new Uri(this.Request.UrlReferrer, "#/error").AbsoluteUri);
					return result; 
				}

				// The response is in Json format; parse it
				var cardInfoList = JsonSerializer.DeserializeFromString<CardInfoList>(responseBody);

				var user = session.TranslateTo<User>();
				user.Id = int.Parse(session.UserAuthId);

				// Associate the access token with the current user
				var oauthTokens = new OAuthTokens { 
					Provider = SiiOAuthProviderInfo.Name,  
					AccessToken = accessToken, 
					AccessTokenSecret = this.TryResolve<IConsumerTokenManager>().GetTokenSecret(accessToken)
				};

				var userOAuthProvider = oauthTokens.TranslateTo<UserOAuthProvider>();
				userOAuthProvider.UserAuthId = user.Id;
				foreach (var cardInfo in cardInfoList.cardids) {
					// TODO: selection based on card status!
					user.SiiContractId = cardInfo.contract;
					user.SiiCustomerId = cardInfo.customer;
					user.SiiMifareId = cardInfo.mifare_id;
					user.SiiTicketNumber = cardInfo.number;

					userOAuthProvider.Items.Add("SiiContractId", cardInfo.contract.ToString());
					userOAuthProvider.Items.Add("SiiCustomerId", cardInfo.customer.ToString());
					userOAuthProvider.Items.Add("SiiMifareId", cardInfo.mifare_id);
					userOAuthProvider.Items.Add("SiiTicketNumber", cardInfo.number);
				}

				// Save it to session..
				session.ProviderOAuthAccess.Add (oauthTokens);

				// And to the DB as well. Both in our user table..
				this.TryResolve<IDbConnectionFactory>().Run(db => db.Save(user));

				// And in the standard oauth table
				this.TryResolve<IDbConnectionFactory>().Run(db => db.Save(userOAuthProvider));

				result.Headers.Add(HttpHeaders.Location, "/");
				return result; 
			}
			catch (Exception ex) {
				result.Headers.Add(HttpHeaders.Location, new Uri(this.Request.UrlReferrer, "#/error").AbsoluteUri);
				return result; 
			}
		}
	}

	[Route("/sii-cardid", "GET")]
	public class SiiCardId: IReturn<SiiCardIdResponse> { }

	public class SiiCardIdResponse {
		public string CardId { get; set; }
	}

	// Given a token (which is in the user infos), retrieve a cardid remotely
	// This can be used to (for example) "refresh" card information (e.g. after
	// a card was re-printed, blocked, etc.)
	public class SiiCardIdService: ServiceStack.ServiceInterface.Service  {  

		public object Get(SiiCardId cardid)
		{
			var session = this.GetSession() as AuthUserSession;
			if (!session.IsAuthenticated)
				return new HttpResult() { StatusCode = HttpStatusCode.Unauthorized };


			var serviceProvider = SiiOAuthProviderInfo.GetServiceDescription();
			var consumer = new WebConsumer(serviceProvider, this.TryResolve<IConsumerTokenManager>());

			//var accessToken = Global.GetTokenManager(SiiOAuth.API_KEY, SiiOAuth.API_SECRET).GetAccessTokenForUser(this.GetSession().UserAuthName);

			var tokens = session.GetOAuthTokens (SiiOAuthProviderInfo.Name);

			// Retrieve the user's card information
			var getURL = SiiOAuthProviderInfo.API_URL + "/cardid.php";
			var endpoint = new MessageReceivingEndpoint(getURL, HttpDeliveryMethods.GetRequest);
			var request = consumer.PrepareAuthorizedRequest(endpoint, tokens.AccessToken);
			var response = request.GetResponse();

			using (var reader =  new StreamReader(response.GetResponseStream())) {
				return new SiiCardIdResponse { CardId = reader.ReadToEnd() };
			}
		}
	}

	[Route("/admin/cards", "GET")]
	public class CardListRequest { }

	// Get a list of the authorized cards, as a list of cards UIDs
	// Useful, for example, to fill card-readers at access gates with the 
	// cards authorized for the day
	// NOTE: this function should only be called over a SECURE connection!
	public class CardList: ServiceStack.ServiceInterface.Service  {  

		public object Get(CardListRequest request) {
			//TODO: Check shared-secret
			//this.Request.Headers.Get ();

			// Get card info from the standard oauth table
			using (var dbConn = this.TryResolve<IDbConnectionFactory>().OpenDbConnection()) {
				var authTokens = dbConn.Select<UserOAuthProvider> ();

				var cards = authTokens.
					Where(authToken => authToken.Items.ContainsKey("SiiMifareId")).
					Select(authToken => authToken.Items["SiiMifareId"]);
				return cards;
			}
		}
	}
}

