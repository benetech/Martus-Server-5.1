/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2001-2007, Beneficent
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

package org.martus.server.main;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.martus.common.ContactInfo;
import org.martus.common.LoggerInterface;
import org.martus.common.MartusUtilities;
import org.martus.common.bulletinstore.BulletinStore;
import org.martus.common.crypto.MartusCrypto.CreateDigestException;
import org.martus.common.crypto.MartusCrypto.CryptoException;
import org.martus.common.crypto.MartusCrypto.DecryptionException;
import org.martus.common.crypto.MartusCrypto.NoKeyPairException;
import org.martus.common.database.BulletinUploadRecord;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.DeleteRequestRecord;
import org.martus.common.database.Database.RecordHiddenException;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.packet.Packet.InvalidPacketException;
import org.martus.common.packet.Packet.SignatureVerificationException;
import org.martus.common.packet.Packet.WrongPacketTypeException;
import org.martus.common.utilities.MartusServerUtilities;


public class ServerBulletinStore extends BulletinStore
{
	public void fillHistoryAndHqCache()
	{
		getHistoryAndHqCache().fillCache();
	}

	public void deleteBulletinRevision(DatabaseKey keyToDelete)
			throws IOException, CryptoException, InvalidPacketException,
			WrongPacketTypeException, SignatureVerificationException,
			DecryptionException, UnsupportedEncodingException,
			NoKeyPairException
	{
		super.deleteBulletinRevision(keyToDelete);
		DatabaseKey burKey = BulletinUploadRecord.getBurKey(keyToDelete);
		deleteSpecificPacket(burKey);			
	}

	public File getIncomingInterimFile(UniversalId uid) throws IOException, RecordHiddenException
	{
		return getWriteableDatabase().getIncomingInterimFile(uid);
	}

	public File getOutgoingInterimFile(UniversalId uid) throws IOException, RecordHiddenException
	{
		return getWriteableDatabase().getOutgoingInterimFile(uid);
	}
	
	public File getOutgoingInterimPublicOnlyFile(UniversalId uid) throws IOException, RecordHiddenException
	{
		return getWriteableDatabase().getOutgoingInterimPublicOnlyFile(uid);
	}
	
	public void writeBur(BulletinHeaderPacket bhp) throws CreateDigestException, IOException, RecordHiddenException
	{
		String localId = bhp.getLocalId();
		String bur = BulletinUploadRecord.createBulletinUploadRecord(localId, getSignatureGenerator());
		writeBur(bhp, bur);
	}
	
	public void writeBur(BulletinHeaderPacket bhp, String bur) throws IOException, RecordHiddenException
	{
		BulletinUploadRecord.writeSpecificBurToDatabase(getWriteableDatabase(), bhp, bur);
	}
	
	public void writeDel(UniversalId uid, DeleteRequestRecord delRecord) throws IOException, RecordHiddenException
	{
		delRecord.writeToDatabase(getWriteableDatabase(), uid);
	}
	
	public void deleteDel(UniversalId uid)
	{
		DatabaseKey delKey = DeleteRequestRecord.getDelKey(uid);
		Database db = getWriteableDatabase();
		if(db.doesRecordExist(delKey))
			db.discardRecord(delKey);
	}

	public boolean doesContactInfoExist(String accountId) throws IOException
	{
		File contactFile = getWriteableDatabase().getContactInfoFile(accountId);
		return contactFile.exists();
	}
	
	public Vector readContactInfo(String accountId) throws IOException
	{
		File contactFile = getWriteableDatabase().getContactInfoFile(accountId);
		return ContactInfo.loadFromFile(contactFile);
	}
	
	public void writeContactInfo(String accountId, Vector contactInfo) throws IOException
	{
		File contactFile = getWriteableDatabase().getContactInfoFile(accountId);
		MartusServerUtilities.writeContatctInfo(accountId, contactInfo, contactFile);
	}
	
	public boolean isHidden(DatabaseKey key)
	{
		return getDatabase().isHidden(key);
	}
	
	public BulletinHeaderPacket saveZipFileToDatabase(File zipFile, String authorAccountId) throws
	Exception
	{
		return saveZipFileToDatabase(zipFile, authorAccountId, System.currentTimeMillis());
	}
	
	public BulletinHeaderPacket saveZipFileToDatabase(File zipFile, String authorAccountId, long mTime) throws
			Exception
	{
		ZipFile zip = null;
		try
		{
			zip = new ZipFile(zipFile);
			BulletinHeaderPacket header = validateZipFilePacketsForImport(zip, authorAccountId);
			importBulletinZipFile(zip, authorAccountId, mTime);
			return header;
		}
		finally
		{
			if(zip != null)
				zip.close();
		}
	}

	public BulletinHeaderPacket validateZipFilePacketsForImport(ZipFile zip, String authorAccountId) throws Exception 
	{
		BulletinHeaderPacket header = MartusUtilities.extractHeaderPacket(authorAccountId, zip, getSignatureVerifier());
		Enumeration entries = zip.entries();
		while(entries.hasMoreElements())
		{
			ZipEntry entry = (ZipEntry)entries.nextElement();
			UniversalId uid = UniversalId.createFromAccountAndLocalId(authorAccountId, entry.getName());
			DatabaseKey trySealedKey = DatabaseKey.createSealedKey(uid);
			if(getDatabase().doesRecordExist(trySealedKey))
			{
				DatabaseKey newKey = header.createKeyWithHeaderStatus(uid);
				if(newKey.isDraft())
					throw new SealedPacketExistsException(entry.getName());
				throw new DuplicatePacketException(entry.getName());
			}
		}
		
		return header;
	}
	
	public Vector getFieldOfficeAccountIdsWithResultCode(String hqAccountId, LoggerInterface logger)
	{
		Vector results = new Vector();
		
		try
		{
			Vector fieldOfficeAccounts = getFieldOffices(hqAccountId);
			if(hadErrorsWhileCacheing())
				throw new Exception();
			results.add(NetworkInterfaceConstants.OK);
			results.addAll(fieldOfficeAccounts);
		}
		catch(Exception e)
		{
			logger.logError(e);
			results.add(NetworkInterfaceConstants.SERVER_ERROR);
		}

		return results;
	}

	public static class DuplicatePacketException extends Exception
	{
		public DuplicatePacketException(String message)
		{
			super(message);
		}

	}
	
	public static class SealedPacketExistsException extends Exception
	{
		public SealedPacketExistsException(String message)
		{
			super(message);
		}

	}
	
}
