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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Collections.Generic;

using ServiceStack.ServiceInterface;
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

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;



namespace SPASSOAuthClientExample {
	public static class SiiOAuthProviderInfo {

		public static string Name = "SII";

		public static String API_URL = "https://www.sii.bz.it/oAuth";
		public static String API_KEY = "HERE_GOES_YOUR_CLIENT_KEY";
		public static String API_SECRET = "USE_RSA_KEY";
		public static String CALLBACK_URL = "http://your_domain/sii-auth-callback";

		static String requestURL = API_URL + "/request.php";
		static String accessURL = API_URL + "/access.php";
		static String authorizeURL = API_URL + "/authorize.php";
		static String certificateFileName = "path_to_certificate.pem";
		static String privateKeyFileName = "path_to_private.pem";

		private static byte[] PEM (string type, string pem)
		{
			string header = String.Format ("-----BEGIN {0}-----", type);
			string footer = String.Format ("-----END {0}-----", type);
			int start = pem.IndexOf (header) + header.Length;
			int end = pem.IndexOf (footer, start);
			string base64 = pem.Substring (start, (end - start)).Replace("\n", "");
			return Convert.FromBase64String (base64);
		}


		private static X509Certificate2 BuildCertificate() {

			var certificatePem = File.ReadAllText(certificateFileName).Replace("\n", "");
			//var privateKeyPem = File.ReadAllText(privateKeyFileName).Replace("\n", "");

			var certificate = new X509Certificate2 (PEM ("CERTIFICATE", certificatePem));

			using (var reader = File.OpenText(privateKeyFileName)) { // file containing RSA PKCS1 private key
				var keyParams = (RsaPrivateCrtKeyParameters)new PemReader(reader).ReadObject(); 

				//var keyPair = (AsymmetricCipherKeyPair)obj;
				//RsaPrivateCrtKeyParameters keyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;
				RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(keyParams);

				RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider();
				rsaKey.ImportParameters(rsaParameters);

				certificate.PrivateKey = rsaKey;
			}

			return certificate;
		}

		public static ServiceProviderDescription GetServiceDescription()
		{
			return new ServiceProviderDescription
			{
				AccessTokenEndpoint = new MessageReceivingEndpoint(accessURL, HttpDeliveryMethods.PostRequest),
				RequestTokenEndpoint = new MessageReceivingEndpoint(requestURL, HttpDeliveryMethods.PostRequest),
				UserAuthorizationEndpoint = new MessageReceivingEndpoint(authorizeURL, HttpDeliveryMethods.GetRequest),
				TamperProtectionElements = new ITamperProtectionChannelBindingElement[] { 
					new RsaSha1ConsumerSigningBindingElement(BuildCertificate()) },
				ProtocolVersion = ProtocolVersion.V10a
			};
		}
	}

}

