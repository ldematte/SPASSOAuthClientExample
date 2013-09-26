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

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using ServiceStack.Common;
using ServiceStack.OrmLite;
using ServiceStack.ServiceInterface;
using ServiceStack.ServiceInterface.Auth;
using ServiceStack.Text;

namespace SPASSOAuthClientExample {
	public class CustomUserSession : AuthUserSession
	{
		public string CustomId { get; set; }

		public override void OnAuthenticated(IServiceBase authService, IAuthSession session, IOAuthTokens tokens, Dictionary<string, string> authInfo)
		{
			base.OnAuthenticated(authService, session, tokens, authInfo);

			//Populate all matching fields from this session to our own custom User table
			var user = session.TranslateTo<User>();
			user.Id = int.Parse(session.UserAuthId);

			foreach (var authToken in session.ProviderOAuthAccess)
			{
				if (authToken.Provider == SiiOAuthProviderInfo.Name)
				{
					user.SiiContractId = int.Parse(authToken.Items ["SiiContractId"]);
					user.SiiCustomerId = int.Parse(authToken.Items["SiiCustomerId"]);
					user.SiiMifareId = authToken.Items["SiiCustomerId"];
					user.SiiTicketNumber = authToken.Items["SiiCustomerId"];
				}
			}

//			var user = Db.QueryById<User>(userProfile.Id);
//			userProfile.PopulateWith(user);
//
//			var userAuths = Db.Select<UserOAuthProvider>("UserAuthId = {0}", session.UserAuthId.ToInt());

//			if (AppHost.AppConfig.AdminUserNames.Contains(session.UserAuthName)
//			    && !session.HasRole(RoleNames.Admin))
//			{
//				using (var assignRoles = authService.ResolveService<AssignRolesService>())
//				{
//					assignRoles.Post(new AssignRoles {
//						UserName = session.UserAuthName,
//						Roles = { RoleNames.Admin }
//					});
//				}
//			}

			//Resolve the DbFactory from the IOC and persist the user info
			authService.TryResolve<IDbConnectionFactory>().Run(db => db.Save(user));
		}
	}
}

