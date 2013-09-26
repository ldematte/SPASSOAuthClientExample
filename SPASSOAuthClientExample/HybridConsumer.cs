namespace DotNetOpenAuth.OAuth {
	using System;
	using System.Collections.Generic;
	using System.Diagnostics.CodeAnalysis;
	using DotNetOpenAuth.Messaging;
	using DotNetOpenAuth.OAuth;
	using DotNetOpenAuth.OAuth.ChannelElements;
	using DotNetOpenAuth.OAuth.Messages;


	public class HybridConsumer : ConsumerBase {

		public HybridConsumer(ServiceProviderDescription serviceDescription, IConsumerTokenManager tokenManager)
			: base(serviceDescription, tokenManager) {
		} 

		public void RequestUserAuthorization(Uri callback, IDictionary<string, string> requestParameters, IDictionary<string, string> redirectParameters, out string requestToken) {
			var message = this.PrepareRequestUserAuthorization(callback, requestParameters, redirectParameters, out requestToken);
			var response = this.Channel.PrepareResponse(message);
			response.Send ();
		}
	}
}

