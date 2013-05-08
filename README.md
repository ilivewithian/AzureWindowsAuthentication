Azure Windows Authentication
============================

This is a simple authentication module that designed to be added to an azure web role. 

**This is not secure. You have been warned.**

This is simply for use on demo websites and the like, it is in no way secure, credentials are passed in plain text and and could easily be picked up by an individual watching web traffic.

With that understood, this can be installed via Nuget:

    Install-Package  AzureWindowsAuthentication

Set the username, password and realm via the appSettings

	<add key="AuthModule.Realm" value="SomeRealm" />
	<add key="AuthModule.Username" value="SomeUser" />
	<add key="AuthModule.Password" value="SomePassword" />

Any questions? Feel free to get in touch.