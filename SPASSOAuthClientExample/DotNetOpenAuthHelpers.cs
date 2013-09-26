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

using ServiceStack.Common.Web;
using DotNetOpenAuth.Messaging;

namespace SPASSOAuthClientExample {
	public static class DotNetOpenAuthHelpers {
		// Transform a DotNetOpenAuth response to a ServiceStack HttpResult
		// (it is very simila to the AsActionResult method in DotNetOpenAuth, 
		// but tailored to ServiceStack's HttpResult
		public static HttpResult AsHttpResult(this OutgoingWebResponse authResponse) {
			
			var result = new HttpResult (authResponse.Body, authResponse.Status);
			foreach (string header in authResponse.Headers.AllKeys)
				result.Headers.Add (header, authResponse.Headers [header]);

			foreach (string cookieName in authResponse.Cookies) {
				var cookie = authResponse.Cookies [cookieName];
				result.SetCookie (cookieName, cookie.Value, cookie.Expires, cookie.Path);
			}	

			return result;
		}
	}
}

