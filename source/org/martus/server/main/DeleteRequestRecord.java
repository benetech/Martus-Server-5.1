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

import java.io.IOException;

import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.FileDatabase;
import org.martus.common.packet.UniversalId;
import org.martus.common.utilities.MartusServerUtilities;

public class DeleteRequestRecord
{
	
	public DeleteRequestRecord(String originalClientDeleteRequestToUse)
	{
		timeStamp = MartusServerUtilities.createTimeStamp();
		originalClientRequest = originalClientDeleteRequestToUse;
	}
	
	public String getDelData() 
	{
		String contents = 
			DRAFT_DELETE_REQUEST_IDENTIFIER + newline +
			timeStamp + newline +
			originalClientRequest + newline;
	return contents;
	}
	
	public void writeSpecificDelToDatabase(Database db, UniversalId uid)
		throws IOException, Database.RecordHiddenException
	{
		db.writeRecord(getDelKey(uid), getDelData());
	}
	
	public static DatabaseKey getDelKey(UniversalId id)
	{
		UniversalId burUid = UniversalId.createFromAccountAndLocalId(id.getAccountId(), FileDatabase.DEL_PREFIX + id.getLocalId());
		return DatabaseKey.createDraftKey(burUid);
	}

	private final static String DRAFT_DELETE_REQUEST_IDENTIFIER = "Martus Draft Delete Request 1.0";
	private final static String newline = "\n";

	private String originalClientRequest;
	private String timeStamp;
}
