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

package org.martus.server.formirroring;

import java.util.Iterator;
import java.util.Vector;

import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MockMartusSecurity;
import org.martus.common.database.DatabaseKey;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.UniversalId;
import org.martus.util.Base64;

class FakeServerSupplier implements ServerSupplierInterface
{
	FakeServerSupplier() throws Exception
	{
		accountsToMirror = new Vector();
		bulletinsToMirror = new Vector();
		security = MockMartusSecurity.createServer();
		
		returnZipData = Base64.encode("zip data".getBytes("UTF-8"));
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
	
	void addBur(String accountId, String localId, String bur)
	{
		burAccountId = accountId;
		burLocalId = localId;
		burContents = bur;
	}
	
	int getChunkSize()
	{
		try
		{
			return Base64.decode(returnZipData).length;
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
			e.printStackTrace();
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
	
	public String getBulletinUploadRecord(String authorAccountId, String bulletinLocalId)
	{
		if(!authorAccountId.equals(burAccountId))
			return null;
		if(!bulletinLocalId.equals(burLocalId))
			return null;
		return burContents;
	}
	
	public Vector getBulletinChunkWithoutVerifyingCaller(String authorAccountId, String bulletinLocalId,
			int chunkOffset, int maxChunkSize)
	{
		gotAccount = authorAccountId;
		gotLocalId = bulletinLocalId;
		gotChunkOffset = chunkOffset;
		gotMaxChunkSize = maxChunkSize;

		int totalLen = getChunkSize();
		if(returnResultTag == NetworkInterfaceConstants.CHUNK_OK)
			totalLen *= 3;

		Vector result = new Vector();
		result.add(returnResultTag);
		result.add(new Integer(totalLen));
		result.add(new Integer(getChunkSize()));
		result.add(returnZipData);
		return result;
	}
	
	public void log(String message)
	{
	}

	String authorizedCaller;
	String returnZipData;
	String returnResultTag;

	String burAccountId;
	String burLocalId;
	String burContents;

	MartusCrypto security;
	Vector accountsToMirror;
	Vector bulletinsToMirror;
	
	String gotAccount;
	String gotLocalId;
	int gotChunkOffset;
	int gotMaxChunkSize;

}
