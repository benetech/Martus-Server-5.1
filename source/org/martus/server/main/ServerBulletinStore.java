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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Vector;
import java.util.zip.ZipException;

import org.martus.common.BulletinStore;
import org.martus.common.ContactInfo;
import org.martus.common.crypto.MartusCrypto.CreateDigestException;
import org.martus.common.crypto.MartusCrypto.CryptoException;
import org.martus.common.crypto.MartusCrypto.DecryptionException;
import org.martus.common.crypto.MartusCrypto.NoKeyPairException;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.Database.RecordHiddenException;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.packet.Packet.InvalidPacketException;
import org.martus.common.packet.Packet.SignatureVerificationException;
import org.martus.common.packet.Packet.WrongAccountException;
import org.martus.common.packet.Packet.WrongPacketTypeException;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.common.utilities.MartusServerUtilities.DuplicatePacketException;
import org.martus.common.utilities.MartusServerUtilities.SealedPacketExistsException;


public class ServerBulletinStore extends BulletinStore
{

	public void deleteBulletinRevision(DatabaseKey keyToDelete)
			throws IOException, CryptoException, InvalidPacketException,
			WrongPacketTypeException, SignatureVerificationException,
			DecryptionException, UnsupportedEncodingException,
			NoKeyPairException
	{
		super.deleteBulletinRevision(keyToDelete);
		DatabaseKey burKey = MartusServerUtilities.getBurKey(keyToDelete);
		getWriteableDatabase().discardRecord(burKey);			
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
	
	public BulletinHeaderPacket saveZipFileToDatabase(String authorAccountId, File zipFile) throws ZipException, InvalidPacketException, SignatureVerificationException, DecryptionException, IOException, RecordHiddenException, SealedPacketExistsException, DuplicatePacketException, WrongAccountException
	{
		return MartusServerUtilities.saveZipFileToDatabase(getWriteableDatabase(), authorAccountId, zipFile, getSignatureGenerator());
	}
	
	public void writeBur(BulletinHeaderPacket bhp) throws CreateDigestException, IOException, RecordHiddenException
	{
		String localId = bhp.getLocalId();
		String bur = MartusServerUtilities.createBulletinUploadRecord(localId, getSignatureGenerator());
		writeBur(bhp, bur);
	}
	
	public void writeBur(BulletinHeaderPacket bhp, String bur) throws IOException, RecordHiddenException
	{
		MartusServerUtilities.writeSpecificBurToDatabase(getWriteableDatabase(), bhp, bur);
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
}
