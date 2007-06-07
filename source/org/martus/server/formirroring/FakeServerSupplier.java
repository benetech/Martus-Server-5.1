/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002-2007, Beneficent
Technology, Inc. (The Benetech Initiative).

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

package org.martus.server.formirroring;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import org.martus.common.bulletin.BulletinConstants;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MockMartusSecurity;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.Database.RecordHiddenException;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.UniversalId;
import org.martus.util.StreamableBase64;

class FakeServerSupplier implements ServerSupplierInterface
{
	FakeServerSupplier() throws Exception
	{
		accountsToMirror = new Vector();
		bulletinsToMirror = new Vector();
		availableIdsToMirror = new Vector();
		security = MockMartusSecurity.createOtherServer();
		
		burContentsDraft = new HashMap();
		burContentsSealed = new HashMap();
		zipData = new HashMap();
	}

	void addAccountToMirror(String accountId)
	{
		accountsToMirror.add(accountId);
	}
	
	void addBulletinToMirror(DatabaseKey key, String sig)
	{
		Vector data = new Vector();
		data.add(key.getUniversalId());
		data.add(sig);
		bulletinsToMirror.add(data);
	}
	
	void addAvailableIdsToMirror(Database db, DatabaseKey key, String sig) throws IOException, RecordHiddenException
	{
		BulletinMirroringInformation bulletinInfo = new BulletinMirroringInformation(db, key, sig);
		Vector data = bulletinInfo.getInfoWithUniversalId();
		availableIdsToMirror.add(data);
	}

	void addBur(UniversalId uid, String bur, String status)
	{
		if(status.equals(BulletinConstants.STATUSDRAFT))
			burContentsDraft.put(uid,bur);
		else
			burContentsSealed.put(uid,bur);
	}
	
	void addZipData(UniversalId uid, String zipDataToUse)
	{
		zipData.put(uid, zipDataToUse);
	}
	
	int getChunkSize(UniversalId uid)
	{
		try
		{
			return StreamableBase64.decode((String)zipData.get(uid)).length;
		}
		catch(Exception nothingWeCanDo)
		{
			return 0;
		}
	}
	
	public MartusCrypto getSecurity()
	{
		return security;
	}
	
	public Vector getPublicInfo()
	{
		try
		{
			Vector result = new Vector();
			result.add(security.getPublicKeyString());
			result.add(security.getSignatureOfPublicKey());
			return result;
		}
		catch (Exception e)
		{
			logError(e);
			return null;
		}
	}
	
	public boolean isAuthorizedForMirroring(String callerAccountId)
	{
		return callerAccountId.equals(authorizedCaller);
	}

	public Vector listAccountsForMirroring()
	{
		return accountsToMirror;
	}

	public Vector listBulletinsForMirroring(String authorAccountId)
	{
		Vector bulletins = new Vector();
		for (Iterator b = bulletinsToMirror.iterator(); b.hasNext();)
		{
			Vector data = (Vector)b.next();
			UniversalId uid = (UniversalId)data.get(0);
			if(authorAccountId.equals(uid.getAccountId()))
			{
				Vector info = new Vector();
				info.add(uid.getLocalId());
				info.add(data.get(1));
				bulletins.add(info);
			}
		}
		return bulletins;
	}
	
	public Set listAvailableIdsForMirroring(String authorAccountId)
	{
		Set bulletins = new HashSet();
		for (Iterator b = availableIdsToMirror.iterator(); b.hasNext();)
		{
			Vector data = (Vector)b.next();
			UniversalId uid = (UniversalId)data.get(0);
			if(authorAccountId.equals(uid.getAccountId()))
			{
				Vector info = new Vector();
				info.add(uid.getLocalId());
				for (int i = 1; i < data.size(); ++i)
				{
					info.add(data.get(i));
				}
				bulletins.add(info);
			}
		}
		return bulletins;
	}
	
	public String getBulletinUploadRecord(String authorAccountId, String bulletinLocalId)
	{
		UniversalId uid = UniversalId.createFromAccountAndLocalId(authorAccountId, bulletinLocalId);
		String bur = (String)burContentsSealed.get(uid);
		if(bur != null)
			return bur;
		return (String)burContentsDraft.get(uid);
	}
	
	public Vector getBulletinChunkWithoutVerifyingCaller(String authorAccountId, String bulletinLocalId,
			int chunkOffset, int maxChunkSize)
	{
		gotAccount = authorAccountId;
		gotLocalId = bulletinLocalId;
		gotChunkOffset = chunkOffset;
		gotMaxChunkSize = maxChunkSize;
		UniversalId uid = UniversalId.createFromAccountAndLocalId(authorAccountId, bulletinLocalId);

		int totalLen = getChunkSize(uid);
		if(returnResultTag == NetworkInterfaceConstants.CHUNK_OK)
			totalLen *= 3;

		Vector result = new Vector();
		result.add(returnResultTag);
		result.add(new Integer(totalLen));
		result.add(new Integer(getChunkSize(uid)));
		result.add(zipData.get(uid));
		return result;
	}
	
	public void log(String message){}
	public void logError(String message){}
	public void logError(Exception e){}
	public void logError(String message, Exception e){}
	public void logInfo(String message){}
	public void logNotice(String message){}
	public void logWarning(String message){}
	public void logDebug(String message){}
	
	String authorizedCaller;
	String returnResultTag;

	HashMap burContentsDraft;
	HashMap burContentsSealed;
	HashMap zipData;

	MartusCrypto security;
	Vector accountsToMirror;
	Vector bulletinsToMirror;
	Vector availableIdsToMirror;
	
	String gotAccount;
	String gotLocalId;
	int gotChunkOffset;
	int gotMaxChunkSize;

}
