/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2001-2004, Beneficent
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
package org.martus.server.forclients;

import java.io.File;
import java.util.Vector;

import org.martus.common.LoggerForTesting;
import org.martus.common.crypto.MartusSecurity;
import org.martus.common.test.TestCaseEnhanced;
import org.martus.util.DirectoryUtils;


public class TestAuthorizeLog extends TestCaseEnhanced
{
	public TestAuthorizeLog(String name)
	{
		super(name);
	}
	
	public void setUp() throws Exception
	{
		MartusSecurity security = new MartusSecurity();
		security.createKeyPair(512);
		tempDir = createTempDirectory();
		File authorizeLogFile = new File(tempDir, AuthorizeLog.AUTHORIZE_LOG_FILENAME);
		authorizeLogFile.deleteOnExit();
		authorized = new AuthorizeLog(security, new LoggerForTesting(), authorizeLogFile);
	}
	
	public void tearDown()
	{
		DirectoryUtils.deleteEntireDirectoryTree(tempDir);
	}
	
	public void testAuthorizeLogLoadSaveFile() throws Exception
	{
		authorized.loadFile();
		String lineToAdd = "date	publicCode	group";
		authorized.appendToFile(new AuthorizeLogEntry(lineToAdd));
		authorized.loadFile();
	}
	
	public void testGetAuthorizedClientStrings() throws Exception
	{
		String newClient = "date2	newClientPublicCode	group2";
		authorized.appendToFile(new AuthorizeLogEntry(newClient));
		Vector currentClients = authorized.getAuthorizedClientStrings();
		assertContains("new client not added?", newClient, currentClients);
		authorized.loadFile();
		Vector currentClients2 = authorized.getAuthorizedClientStrings();
		assertContains("new client not added after load?", newClient, currentClients2);
	}
	
	AuthorizeLog authorized;
	File tempDir;
}
