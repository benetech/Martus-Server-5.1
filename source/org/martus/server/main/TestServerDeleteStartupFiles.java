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
package org.martus.server.main;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Vector;

import org.martus.common.test.TestCaseEnhanced;
import org.martus.server.forclients.MockMartusServer;


public class TestServerDeleteStartupFiles extends TestCaseEnhanced
{
	public TestServerDeleteStartupFiles(String name)
	{
		super(name);
	}

	public void testBasics() throws Exception
	{
		MockMartusServer testServer = new MockMartusServer();
		testServer.enterSecureMode();
		File triggerDirectory = testServer.getTriggerDirectory();
		triggerDirectory.deleteOnExit();
		triggerDirectory.mkdir();
		triggerDirectory.delete();
		
		File startupDirectory = testServer.getStartupConfigDirectory();
		startupDirectory.deleteOnExit();
		startupDirectory.mkdir();
		
		assertTrue("StartupDirectory should exist.", startupDirectory.exists());

		Vector startupFiles = testServer.getDeleteOnStartupFiles();
		createFiles(startupFiles);
		Vector unexpectedFile = new Vector();
		File tmpFile = new File(startupDirectory, "$$$unexpected.txt");
		tmpFile.deleteOnExit();
		unexpectedFile.add(tmpFile);
		createFiles(unexpectedFile);
		assertTrue("unexpected file doesn't exist?", tmpFile.exists());
		assertTrue("Should be an unexpected file", testServer.anyUnexpectedFilesInStartupDirectory());
		assertFalse("Directory will contain unexpected file", testServer.deleteStartupFiles());

		tmpFile.delete();
		createFiles(startupFiles);
		assertFalse("Should not be any unexpected files", testServer.anyUnexpectedFilesInStartupDirectory());
		assertTrue("Directory should be empty", testServer.deleteStartupFiles());
		
		startupDirectory.delete();
		assertFalse("StartupDirectory should not still exist.", startupDirectory.exists());
	}

	private void createFiles(Vector startupFiles) throws FileNotFoundException, IOException
	{
		for(int i = 0; i<startupFiles.size(); ++i )
		{	
			File tmp = (File)startupFiles.get(i);
			tmp.deleteOnExit();
			FileOutputStream out = new FileOutputStream(tmp);
			out.write(1);
			out.close();
		}
	}
}
