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

using Funq;
using ServiceStack.WebHost.Endpoints;
using DotNetOpenAuth.OAuth.ChannelElements;
using ServiceStack.ServiceInterface;
using ServiceStack.ServiceInterface.Auth;
using ServiceStack.ServiceInterface.Admin;
using ServiceStack.CacheAccess;
using ServiceStack.CacheAccess.Providers;
using ServiceStack.Configuration;
using ServiceStack.OrmLite;
using ServiceStack.OrmLite.Sqlite;
using ServiceStack.Common.Utils;

namespace SPASSOAuthClientExample {
	public class AppHost : AppHostBase { 
		//Tell Service Stack the name of your application and where to find your web services 
		public AppHost() : base("Hello Web Services", typeof(SiiOAuthRequestService).Assembly) { } 
		public override void Configure(Container container) { 

			//Set JSON web services to return idiomatic JSON camelCase properties
			ServiceStack.Text.JsConfig.EmitCamelCaseNames = true;

			Plugins.Add(new AuthFeature(() => new CustomUserSession(), new IAuthProvider[] {
				new CredentialsAuthProvider()
			}));

			//Provide service for new users to register so they can login with supplied credentials.
			Plugins.Add(new RegistrationFeature());

			container.Register<ICacheClient>(new MemoryCacheClient());

			//The AppSettings is used by most Auth Providers to access additional information stored the Web.Config:
			var appSettings = new AppSettings();

			var connStr = "./db.sqlite".MapAbsolutePath ();
			container.Register<IDbConnectionFactory> (
				new OrmLiteConnectionFactory(connStr, //TODO: put ConnectionString in Web.Config	                                 
			                             SqliteOrmLiteDialectProvider.Instance));

			//Use OrmLite DB Connection to persist the UserAuth and AuthProvider info
			container.Register<IUserAuthRepository>(c => new OrmLiteAuthRepository(c.Resolve<IDbConnectionFactory>())); 

			container.Register<IConsumerTokenManager>(c => new InMemoryTokenManager(SiiOAuthProviderInfo.API_KEY, SiiOAuthProviderInfo.API_SECRET));

			//Create your own custom User table
			var dbFactory = container.Resolve<IDbConnectionFactory>();
			dbFactory.Run(db => db.CreateTableIfNotExists<User>());

			//If using and RDBMS to persist UserAuth, we must create required tables
			var authRepo = (OrmLiteAuthRepository)container.Resolve<IUserAuthRepository>(); 
			if (appSettings.Get("RecreateAuthTables", false))
				authRepo.DropAndReCreateTables(); //Drop and re-create all Auth and registration tables
			else
				authRepo.CreateMissingTables(); //Create only the missing tables

			Plugins.Add(new RequestLogsFeature());

		} 
	} 
}

