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

namespace SPASSOAuthClientExample {

	// The CardInfo data structure is returned as a Json object from our
	// authentication service, which is in PHP. PHP serializes datetime in 
	// a rather peculiar way.. let's represent it with a POCO
	public class PhpDateTime {
		public string date { get; set; }
		public int timezone_type {get; set; }
		public string timezone { get; set; }
	}

	// And we also have an helper to translate it to a proper DateTime
	public static class DateTimeHelpers {

		public static DateTime? AsDateTime(this PhpDateTime phpDate) {
			DateTime dateTime;
			if (phpDate == null || !DateTime.TryParse(phpDate.date, out dateTime))
				return null;
			return dateTime;
		}
	}


	public class CardInfoList {
		public List<CardInfo> cardids {
			get;
			set;
		}
	}

	// The POCO for the Json response to /api/cards
	public class CardInfo {
		public int id { get; set; }

		public int ticket_type { get; set; }
		public int contract { get; set; }
		public int customer { get; set; }
		public int request { get; set; }
		public int? old_ticket { get; set; }
		public string number { get; set; }
		public string mifare_id { get; set; }

		public int ticket_office { get; set; }

		public PhpDateTime valid_from { get; set; }
		public PhpDateTime valid_until { get; set; }

		public int ticket_status { get; set; }
		public int status_user { get; set; }
		public PhpDateTime status_time { get; set; }

		public int create_user { get; set; }
		public PhpDateTime create_time { get; set; }

		public int delete_user { get; set; }
		public PhpDateTime delete_time { get; set; }

	}
}

