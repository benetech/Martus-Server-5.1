/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2006, Beneficent
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

import java.io.BufferedReader;
import java.io.StringReader;

import org.martus.common.database.DatabaseKey;
import org.martus.common.packet.UniversalId;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.util.TestCaseEnhanced;

public class TestDeleteRequestPackets extends TestCaseEnhanced
{

	public TestDeleteRequestPackets(String name)
	{
		super(name);
	}

	public void testCreateDELRecord() throws Exception
	{
		String delRequestData = "Delete b1 test data";
		DraftDeleteRequest delRequest = new DraftDeleteRequest(delRequestData);
		String delData = delRequest.getDelData();
		BufferedReader reader = new BufferedReader(new StringReader(delData));
		String gotFileTypeIdentifier = reader.readLine();
		assertEquals("Martus Draft Delete Request 1.0", gotFileTypeIdentifier);
		String gotTimeStamp = reader.readLine();
		String now = MartusServerUtilities.createTimeStamp();
		assertStartsWith(now.substring(0, 13), gotTimeStamp);
		assertEquals(delRequestData, reader.readLine());
		reader.close();
	}
	
	public void testGetDELKey() throws Exception
	{
		UniversalId uid = UniversalId.createDummyUniversalId();
		DatabaseKey draftDELKey = DraftDeleteRequest.getDelKey(uid);
		assertEquals("DEL-" + uid.getLocalId(), draftDELKey.getLocalId());
	}
	
}
