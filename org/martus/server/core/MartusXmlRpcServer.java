/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002,2003, Beneficent
Technology, Inc. (Benetech).

Martus is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later
version with the additions and exceptions described in the
accompanying Martus license file entitled "license.txt".

It is distributed WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, including warranties of fitness of purpose or
merchantability.  See the accompanying Martus License and
GPL license for more details on the required license terms
for this software.

You should have received a copy of the GNU General Public
License along with this program; if not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.

*/

package org.martus.server.core;

import java.net.InetAddress;


public class MartusXmlRpcServer
{
	public static WebServerWithClientId createNonSSLXmlRpcServer(Object server, int port, InetAddress address)
	{
		try
		{
			WebServerWithClientId webServer = new WebServerWithClientId(port, address);
			webServer.addHandler("MartusServer", server);
			return webServer;
		}
		catch (Exception e)
		{
			System.err.println("createNonSSLXmlRpcServer " + port + ": " + e.toString());
			e.printStackTrace();
		}
		return null;
	}
	
	public static MartusSecureWebServer createSSLXmlRpcServer(Object server, String destObjectName, int port, InetAddress address)
	{
		try
		{
			MartusSecureWebServer secureWebServer = new MartusSecureWebServer(port, address);
			secureWebServer.addHandler(destObjectName, server);
			return secureWebServer;
		}
		catch (Exception e)
		{
			System.err.println("createSSLXmlRpcServer " + port + ": " + e);
			System.err.println( e.getMessage() );
			e.printStackTrace();
		}
		return null;
	}
}
