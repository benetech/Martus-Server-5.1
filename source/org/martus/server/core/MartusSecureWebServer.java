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

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;

import org.martus.common.crypto.MartusCrypto;

public class MartusSecureWebServer extends WebServerWithClientId
{
	public MartusSecureWebServer(int port) throws IOException
	{
		this(port, null);
	}

	public MartusSecureWebServer(int port, InetAddress internetAddress) throws IOException
	{
		super(port, internetAddress);
	}
	
	public ServerSocket createServerSocket(int port, int backlog, java.net.InetAddress add)
			throws Exception
	{
		try
	    {
			SSLContext sslContext = createSSLContext();
			SSLServerSocketFactory sf = sslContext.getServerSocketFactory();

	    	ServerSocket ss = sf.createServerSocket( port, backlog, add);
	    	return ss;
	    }
	    catch(Exception e)
	    {
	    	System.out.println("createServerSocket: " + e);
	    	System.out.println(e.getMessage());
	    	e.printStackTrace();
	    }
	    return null;
	}
	
	SSLContext createSSLContext() throws Exception
	{
		SSLContext sslContext = SSLContext.getInstance( "TLS" );
		sslContext.init( security.createKeyManagers(), null, null );
		return sslContext;
	}
	
	
	public static MartusCrypto security;
}
