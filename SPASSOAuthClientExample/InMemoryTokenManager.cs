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
using System.Collections.Generic;
using DotNetOpenAuth.OAuth.ChannelElements;
using DotNetOpenAuth.OAuth.Messages;

namespace SPASSOAuthClientExample
{
	// A very basic token manager, which uses memory as a temporary store for requests and 
	// access tokens (Access tokens are then definitely serialized with the user account on
	// the DB)
	public class InMemoryTokenManager : IConsumerTokenManager
	{
		private Dictionary<string, string> requestTokensAndSecrets = new Dictionary<string, string> ();
		private Dictionary<string, string> accessTokensAndSecrets = new Dictionary<string, string> ();

		/// <summary>
		/// Initializes a new instance of the <see cref="InMemoryTokenManager"/> class.
		/// </summary>
		/// <param name="consumerKey">The consumer key.</param>
		/// <param name="consumerSecret">The consumer secret.</param>
		public InMemoryTokenManager(string consumerKey, string consumerSecret) {
			if (String.IsNullOrEmpty(consumerKey)) {
				throw new ArgumentNullException("consumerKey");
			}

			this.ConsumerKey = consumerKey;
			this.ConsumerSecret = consumerSecret;
		}

		/// <summary>
		/// Gets the consumer key.
		/// </summary>
		/// <value>The consumer key.</value>
		public string ConsumerKey { get; private set; }

		/// <summary>
		/// Gets the consumer secret.
		/// </summary>
		/// <value>The consumer secret.</value>
		public string ConsumerSecret { get; private set; }

		#region ITokenManager Members

		public string GetConsumerSecret(string consumerKey)
		{
			if (consumerKey == this.ConsumerKey)
			{
				return this.ConsumerSecret;
			}
			else
			{
				throw new ArgumentException("Unrecognized consumer key.", "consumerKey");
			}
		}

		public string GetTokenSecret(string token)
		{
			if (requestTokensAndSecrets.ContainsKey (token))
				return requestTokensAndSecrets [token];
			else 
				return accessTokensAndSecrets [token];
		}

		public void StoreNewRequestToken(UnauthorizedTokenRequest request, ITokenSecretContainingMessage response)
		{
			this.requestTokensAndSecrets[response.Token] = response.TokenSecret;
		}

		public void ExpireRequestTokenAndStoreNewAccessToken(string consumerKey, string requestToken, string accessToken, string accessTokenSecret)
		{
			this.requestTokensAndSecrets.Remove(requestToken);
			this.accessTokensAndSecrets[accessToken] = accessTokenSecret;
		}

		/// <summary>
		/// Classifies a token as a request token or an access token.
		/// </summary>
		/// <param name="token">The token to classify.</param>
		/// <returns>Request or Access token, or invalid if the token is not recognized.</returns>
		public TokenType GetTokenType(string token)
		{
			if (requestTokensAndSecrets.ContainsKey (token))
				return TokenType.RequestToken;
			else if (accessTokensAndSecrets.ContainsKey (token))
				return TokenType.AccessToken;
			else
				return TokenType.InvalidToken;
		}

		#endregion
	}
}

