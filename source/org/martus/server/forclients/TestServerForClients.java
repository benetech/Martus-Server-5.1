/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002-2004, Beneficent
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
import java.io.FileOutputStream;
import java.util.Vector;

import org.martus.common.HQKey;
import org.martus.common.HQKeys;
import org.martus.common.bulletin.AttachmentProxy;
import org.martus.common.bulletin.Bulletin;
import org.martus.common.bulletin.BulletinForTesting;
import org.martus.common.bulletin.BulletinLoader;
import org.martus.common.bulletin.BulletinSaver;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MockMartusSecurity;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.MockClientDatabase;
import org.martus.common.database.MockServerDatabase;
import org.martus.common.network.NetworkInterface;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.util.Base64;
import org.martus.util.TestCaseEnhanced;
import org.martus.util.UnicodeWriter;

public class TestServerForClients extends TestCaseEnhanced
{

	public TestServerForClients(String name)
	{
		super(name);
	}

	public static void main(String[] args)
	{
	}

	protected void setUp() throws Exception
	{
		super.setUp();
		TRACE_BEGIN("setUp");

		if(clientSecurity == null)
		{
			clientSecurity = MockMartusSecurity.createClient();
			clientAccountId = clientSecurity.getPublicKeyString();
		}
		
		if(serverSecurity == null)
		{
			serverSecurity = MockMartusSecurity.createServer();
		}
		
		if(testServerSecurity == null)
		{
			testServerSecurity = MockMartusSecurity.createOtherServer();
		}

		if(hqSecurity == null)
		{
			hqSecurity = MockMartusSecurity.createHQ();
		}
		if(tempFile == null)
		{
			tempFile = createTempFileFromName("$$$MartusTestMartusServer");
			tempFile.delete();
		}
		if(clientDatabase == null)
		{
			clientDatabase = new MockClientDatabase();
			b1 = new Bulletin(clientSecurity);
			b1.setAllPrivate(false);
			b1.set(Bulletin.TAGTITLE, "Title1");
			b1.set(Bulletin.TAGPUBLICINFO, "Details1");
			b1.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails1");
			File attachment = createTempFile();
			FileOutputStream out = new FileOutputStream(attachment);
			out.write(b1AttachmentBytes);
			out.close();
			b1.addPublicAttachment(new AttachmentProxy(attachment));
			b1.addPrivateAttachment(new AttachmentProxy(attachment));
			HQKeys keys = new HQKeys();
			HQKey key1 = new HQKey(hqSecurity.getPublicKeyString());
			keys.add(key1);
			b1.setAuthorizedToReadKeys(keys);
			b1.setSealed();
			BulletinSaver.saveToClientDatabase(b1, clientDatabase, true, clientSecurity);
			b1 = BulletinLoader.loadFromDatabase(clientDatabase, DatabaseKey.createSealedKey(b1.getUniversalId()), clientSecurity);
	
			b2 = new Bulletin(clientSecurity);
			b2.set(Bulletin.TAGTITLE, "Title2");
			b2.set(Bulletin.TAGPUBLICINFO, "Details2");
			b2.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails2");
			b2.setSealed();
			BulletinSaver.saveToClientDatabase(b2, clientDatabase, true, clientSecurity);
			
			draft = new Bulletin(clientSecurity);
			draft.set(Bulletin.TAGPUBLICINFO, "draft public");
			draft.setDraft();
			BulletinSaver.saveToClientDatabase(draft, clientDatabase, true, clientSecurity);


			privateBulletin = new Bulletin(clientSecurity);
			privateBulletin.setAllPrivate(true);
			privateBulletin.set(Bulletin.TAGTITLE, "TitlePrivate");
			privateBulletin.set(Bulletin.TAGPUBLICINFO, "DetailsPrivate");
			privateBulletin.set(Bulletin.TAGPRIVATEINFO, "PrivateDetailsPrivate");
			privateBulletin.setSealed();
			BulletinSaver.saveToClientDatabase(privateBulletin, clientDatabase, true, clientSecurity);

			b1ZipString = BulletinForTesting.saveToZipString(clientDatabase, b1, clientSecurity);
			b1ZipBytes = Base64.decode(b1ZipString);
			b1ChunkBytes0 = new byte[100];
			b1ChunkBytes1 = new byte[b1ZipBytes.length - b1ChunkBytes0.length];
			System.arraycopy(b1ZipBytes, 0, b1ChunkBytes0, 0, b1ChunkBytes0.length);
			System.arraycopy(b1ZipBytes, b1ChunkBytes0.length, b1ChunkBytes1, 0, b1ChunkBytes1.length);
			b1ChunkData0 = Base64.encode(b1ChunkBytes0);
			b1ChunkData1 = Base64.encode(b1ChunkBytes1);
			
		}
		
		mockServer = new MockMartusServer(); 
		mockServer.verifyAndLoadConfigurationFiles();
		mockServer.setSecurity(testServerSecurity);
		testServer = mockServer.serverForClients;
		testServerInterface = new ServerSideNetworkHandler(testServer);
		serverDatabase = (MockServerDatabase)mockServer.getDatabase();

		TRACE_END();
	}

	protected void tearDown() throws Exception
	{
		TRACE_BEGIN("tearDown");

		assertEquals("isShutdownRequested", false, mockServer.isShutdownRequested());
		mockServer.deleteAllFiles();
		tempFile.delete();

		TRACE_END();
		super.tearDown();
	}

	public void testBannedClients()
		throws Exception
	{
		TRACE_BEGIN("testBannedClients");

		String clientId = clientSecurity.getPublicKeyString();
		String hqId = hqSecurity.getPublicKeyString();
		testServer.loadBannedClients(new File("test"));
		
		File clientBanned = createTempFile();
		
		UnicodeWriter writer = new UnicodeWriter(clientBanned);
		writer.writeln(clientId);
		writer.close();
		
		String bogusStringParameter = "this is never used in this call. right?";

		testServer.allowUploads(clientId, null);
		testServer.allowUploads(hqId, null);
		testServer.loadBannedClients(clientBanned);

		Vector vecResult = null;
		vecResult = testServer.listMyDraftBulletinIds(clientId, new Vector());
		verifyErrorResult("listMyDraftBulletinIds", vecResult, NetworkInterfaceConstants.REJECTED );
		assertEquals("listMyDraftBulletinIds", 0, testServer.getNumberActiveClients() );
		
		String strResult = testServer.requestUploadRights(clientId, bogusStringParameter);
		assertEquals("requestUploadRights", NetworkInterfaceConstants.REJECTED, strResult );
		assertEquals("requestUploadRights", 0, testServer.getNumberActiveClients() );
		
		strResult = testServer.putBulletinChunk(clientId, clientId, bogusStringParameter, 0, 0, 0, bogusStringParameter);
		assertEquals("putBulletinChunk client banned", NetworkInterfaceConstants.REJECTED, strResult);
		assertEquals("putBulletinChunk client banned", 0, testServer.getNumberActiveClients() );

		strResult = testServer.putBulletinChunk(hqId, clientId, bogusStringParameter, 0, 0, 0, bogusStringParameter);
		assertEquals("putBulletinChunk hq not banned but client is", NetworkInterfaceConstants.REJECTED, strResult);

		File noneBanned = createTempFile();
		writer = new UnicodeWriter(noneBanned);
		writer.writeln("");
		writer.close();
		testServer.loadBannedClients(noneBanned);
		strResult = testServer.putBulletinChunk(hqId, clientId, bogusStringParameter, 0, 0, 0, bogusStringParameter);
		assertEquals("putBulletinChunk hq and client not banned should get invalid data", NetworkInterfaceConstants.INVALID_DATA, strResult);
		testServer.clearCanUploadList();
		testServer.allowUploads(hqId, null);
		assertEquals("putBulletinChunk client can't upload but hq can should get invalid data", NetworkInterfaceConstants.INVALID_DATA, strResult);
		
		testServer.allowUploads(clientId, null);
		testServer.loadBannedClients(clientBanned);
		vecResult = testServer.getBulletinChunk(clientId, clientId, bogusStringParameter, 0, 0);
		verifyErrorResult("getBulletinChunk", vecResult, NetworkInterfaceConstants.REJECTED );
		assertEquals("getBulletinChunk", 0, testServer.getNumberActiveClients() );

		vecResult = testServer.getPacket(clientId, bogusStringParameter, bogusStringParameter, bogusStringParameter);
		verifyErrorResult("getPacket", vecResult, NetworkInterfaceConstants.REJECTED );
		assertEquals("getPacket", 0, testServer.getNumberActiveClients() );

		strResult = testServer.deleteDraftBulletins(clientId, new String[] {bogusStringParameter} );
		assertEquals("deleteDraftBulletins", NetworkInterfaceConstants.REJECTED, strResult);
		assertEquals("deleteDraftBulletins", 0, testServer.getNumberActiveClients() );

		strResult = testServer.putContactInfo(clientId, new Vector() );
		assertEquals("putContactInfo", NetworkInterfaceConstants.REJECTED, strResult);		
		assertEquals("putContactInfo", 0, testServer.getNumberActiveClients() );

		vecResult = testServer.listFieldOfficeDraftBulletinIds(hqId, clientId, new Vector());
		verifyErrorResult("listFieldOfficeDraftBulletinIds1", vecResult, NetworkInterfaceConstants.OK );
		assertEquals("listFieldOfficeDraftBulletinIds1", 0, testServer.getNumberActiveClients() );
		
		vecResult = testServer.listFieldOfficeAccounts(hqId);
		verifyErrorResult("listFieldOfficeAccounts1", vecResult, NetworkInterfaceConstants.OK );
		assertEquals("listFieldOfficeAccounts1", 0, testServer.getNumberActiveClients() );
		
		vecResult = testServer.listFieldOfficeDraftBulletinIds(clientId, clientId, new Vector());
		verifyErrorResult("listFieldOfficeDraftBulletinIds2", vecResult, NetworkInterfaceConstants.REJECTED );
		assertEquals("listFieldOfficeDraftBulletinIds2", 0, testServer.getNumberActiveClients() );
		
		vecResult = testServer.listFieldOfficeAccounts(clientId);
		verifyErrorResult("listFieldOfficeAccounts2", vecResult, NetworkInterfaceConstants.REJECTED );
		assertEquals("listFieldOfficeAccounts2", 0, testServer.getNumberActiveClients() );

		TRACE_END();
	}

	public void testClientCounter()
	{
		TRACE_BEGIN("testClientCounter");

		assertEquals("getNumberActiveClients 1", 0, testServer.getNumberActiveClients());
		
		testServer.clientConnectionStart();
		testServer.clientConnectionStart();
		assertEquals("getNumberActiveClients 2", 2, testServer.getNumberActiveClients());
		
		testServer.clientConnectionExit();
		testServer.clientConnectionExit();
		assertEquals("getNumberActiveClients 3", 0, testServer.getNumberActiveClients());

		TRACE_END();
	}
	
	void verifyErrorResult(String label, Vector vector, String expected )
	{
		assertTrue( label + " error size not at least 1?", vector.size() >= 1);
		assertEquals( label + " error wrong result code", expected, vector.get(0));
	}

	static MartusCrypto clientSecurity;
	static String clientAccountId;
	static MartusCrypto serverSecurity;
	static MartusCrypto testServerSecurity;
	static MartusCrypto hqSecurity;
	static MockClientDatabase clientDatabase;

	static Bulletin b1;
	static byte[] b1ZipBytes;
	static String b1ZipString;
	static byte[] b1ChunkBytes0;
	static byte[] b1ChunkBytes1;
	static String b1ChunkData0;
	static String b1ChunkData1;
	final static byte[] b1AttachmentBytes = {1,2,3,4,4,3,2,1};
	
	static Bulletin b2;
	static Bulletin privateBulletin;
	static Bulletin draft;

	static File tempFile;

	MockMartusServer mockServer; 
	ServerForClients testServer;
	NetworkInterface testServerInterface;
	MockServerDatabase serverDatabase;

}
