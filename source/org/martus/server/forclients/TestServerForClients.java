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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Vector;

import org.martus.common.BulletinStore;
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
import org.martus.common.network.NetworkInterface;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.server.main.MartusServer;
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
		mockServer.setClientListenerEnabled(true);
		mockServer.verifyAndLoadConfigurationFiles();
		mockServer.setSecurity(testServerSecurity);
		testServer = mockServer.serverForClients;
		testServerInterface = new ServerSideNetworkHandler(testServer);

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
	
	public void testListFieldOfficeDraftBulletinIds() throws Exception
	{
		TRACE_BEGIN("testListFieldOfficeDraftBulletinIds");

		mockServer.setSecurity(serverSecurity);

		MartusCrypto fieldSecurity1 = clientSecurity;
		mockServer.allowUploads(fieldSecurity1.getPublicKeyString());

		MartusCrypto nonFieldSecurity = MockMartusSecurity.createOtherClient();
		mockServer.allowUploads(nonFieldSecurity.getPublicKeyString());

		Vector list1 = testServer.listFieldOfficeSealedBulletinIds(hqSecurity.getPublicKeyString(), fieldSecurity1.getPublicKeyString(), new Vector());
		assertNotNull("testListFieldOfficeBulletinSummaries returned null", list1);
		assertEquals("wrong length list 1", 2, list1.size());
		assertNotNull("null id1 [0] list1", list1.get(0));
		assertEquals(NetworkInterfaceConstants.OK, list1.get(0));
		
		MartusCrypto otherServerSecurity = MockMartusSecurity.createOtherServer();

		Bulletin bulletinSealed = new Bulletin(clientSecurity);
		HQKeys keys = new HQKeys();
		HQKey key1 = new HQKey(hqSecurity.getPublicKeyString());
		HQKey key2 = new HQKey(otherServerSecurity.getPublicKeyString());
		keys.add(key1);
		keys.add(key2);
		bulletinSealed.setAuthorizedToReadKeys(keys);
		bulletinSealed.setSealed();
		bulletinSealed.setAllPrivate(true);
		BulletinSaver.saveToClientDatabase(bulletinSealed, clientDatabase, true, clientSecurity);
		mockServer.uploadBulletin(clientSecurity.getPublicKeyString(), bulletinSealed.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, bulletinSealed, clientSecurity));

		Bulletin bulletinDraft = new Bulletin(clientSecurity);
		bulletinDraft.setAuthorizedToReadKeys(keys);
		bulletinDraft.setDraft();
		BulletinSaver.saveToClientDatabase(bulletinDraft, clientDatabase, true, clientSecurity);
		mockServer.uploadBulletin(clientSecurity.getPublicKeyString(), bulletinDraft.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, bulletinDraft, clientSecurity));

		Vector list2 = testServer.listFieldOfficeDraftBulletinIds(hqSecurity.getPublicKeyString(), fieldSecurity1.getPublicKeyString(), new Vector());
		assertEquals("wrong length list2", 2, list2.size());
		assertNotNull("null id1 [0] list2", list2.get(0));
		assertEquals(NetworkInterfaceConstants.OK, list2.get(0));
		String b1Summary = bulletinDraft.getLocalId() + "=" + bulletinDraft.getFieldDataPacket().getLocalId();
		assertContains("missing bulletin Draft?",b1Summary , (Vector)list2.get(1));

		
		Vector list3 = testServer.listFieldOfficeDraftBulletinIds(otherServerSecurity.getPublicKeyString(), fieldSecurity1.getPublicKeyString(), new Vector());
		assertEquals("wrong length list hq2", 2, list3.size());
		assertNotNull("null id1 [0] list hq2", list3.get(0));
		assertEquals(NetworkInterfaceConstants.OK, list3.get(0));
		String b1Summaryhq2 = bulletinDraft.getLocalId() + "=" + bulletinDraft.getFieldDataPacket().getLocalId();
		assertContains("missing bulletin Draft for HQ2?",b1Summaryhq2 , (Vector)list3.get(1));
		
		TRACE_END();
	}

	public void testDeleteDraftBulletinsEmptyList() throws Exception
	{
		TRACE_BEGIN("testDeleteDraftBulletinsEmptyList");

		String[] allIds = {};
		String resultAllOk = testServer.deleteDraftBulletins(clientAccountId, allIds);
		assertEquals("Empty not ok?", NetworkInterfaceConstants.OK, resultAllOk);

		TRACE_END();
	}
	
	public void testDeleteDraftBulletinsThroughHandler() throws Exception
	{
		TRACE_BEGIN("testDeleteDraftBulletinsThroughHandler");

		String[] allIds = uploadSampleDrafts();
		Vector parameters = new Vector();
		parameters.add(new Integer(allIds.length));
		for (int i = 0; i < allIds.length; i++)
			parameters.add(allIds[i]);

		String sig = clientSecurity.createSignatureOfVectorOfStrings(parameters);
		Vector result = testServerInterface.deleteDraftBulletins(clientAccountId, parameters, sig);
		assertEquals("Result size?", 1, result.size());
		assertEquals("Result not ok?", NetworkInterfaceConstants.OK, result.get(0));

		TRACE_END();
	}
		
	public void testDeleteDraftBulletins() throws Exception
	{
		TRACE_BEGIN("testDeleteDraftBulletinsThroughHandler");

		BulletinStore store = mockServer.getStore();

		String[] allIds = uploadSampleDrafts();
		String resultAllOk = testServer.deleteDraftBulletins(clientAccountId, allIds);
		assertEquals("Good 3 not ok?", NetworkInterfaceConstants.OK, resultAllOk);
		assertEquals("Didn't delete all?", 0, store.getBulletinCount());
		
		String[] twoGoodOneBad = uploadSampleDrafts();
		twoGoodOneBad[1] = "Not a valid local id";
		String resultOneBad = testServer.deleteDraftBulletins(clientAccountId, twoGoodOneBad);
		assertEquals("Two good one bad not incomplete?", NetworkInterfaceConstants.INCOMPLETE, resultOneBad);
		assertEquals("Didn't delete two?", 1, store.getBulletinCount());
		
		uploadSampleBulletin();
		int newRecordCount = store.getBulletinCount();
		assertNotEquals("Didn't upload?", 1, newRecordCount);
		String[] justSealed = new String[] {b1.getLocalId()};
		testServer.deleteDraftBulletins(clientAccountId, justSealed);
		assertEquals("Sealed not ok?", NetworkInterfaceConstants.OK, resultAllOk);
		assertEquals("Deleted sealed?", newRecordCount, store.getBulletinCount());

		TRACE_END();
	}

	String[] uploadSampleDrafts() throws Exception
	{
		BulletinStore store = mockServer.getStore();

		assertEquals("db not empty?", 0, store.getBulletinCount());
		Bulletin draft1 = new Bulletin(clientSecurity);
		uploadSampleDraftBulletin(draft1);
		assertEquals("Didn't save 1?", 1, store.getBulletinCount());
		Bulletin draft2 = new Bulletin(clientSecurity);
		uploadSampleDraftBulletin(draft2);
		assertEquals("Didn't save 2?", 2, store.getBulletinCount());
		Bulletin draft3 = new Bulletin(clientSecurity);
		uploadSampleDraftBulletin(draft3);
		assertEquals("Didn't save 3?", 3, store.getBulletinCount());

		return new String[] {draft1.getLocalId(), draft2.getLocalId(), draft3.getLocalId()};
	}

	public void testLoadingMagicWords() throws Exception
	{		
		TRACE_BEGIN("testLoadingMagicWords");

		String sampleMagicWord1 = "kef7873n2";
		String sampleMagicWord2 = "fjk5dlkg8";
		String inactiveMagicWord2 = "#" + sampleMagicWord2;
		String sampleGroup = "group name";
		String sampleMagicWord3 = "Magic3";
		String sampleMagicWord4 = "magic4";
		String sampleMagicWordline3 = sampleMagicWord3 + "	" + sampleGroup;
		String sampleMagicWordline4 = sampleMagicWord4 + "\t" + sampleGroup;
		String nonExistentMagicWord = "ThisIsNotAMagicWord";
		
		File file = testServer.getMagicWordsFile();
		UnicodeWriter writer = new UnicodeWriter(file);
		writer.writeln(sampleMagicWord1);
		writer.writeln(inactiveMagicWord2);
		writer.writeln(sampleMagicWordline3);
		writer.writeln(sampleMagicWordline4);
		writer.close();

		MockMartusServer other = new MockMartusServer(mockServer.getDataDirectory());
		other.setClientListenerEnabled(true);
		other.verifyAndLoadConfigurationFiles();
		MartusCrypto otherServerSecurity = MockMartusSecurity.createOtherServer();
		other.setSecurity(otherServerSecurity);
		
		String worked = other.requestUploadRights("whatever", sampleMagicWord1);
		assertEquals("didn't work?", NetworkInterfaceConstants.OK, worked);
		
		worked = other.requestUploadRights("whatever2", sampleMagicWord1.toUpperCase());
		assertEquals("should ignore case sensitivity", NetworkInterfaceConstants.OK, worked);
		
		worked = other.requestUploadRights("whatever2", sampleMagicWord3);
		assertEquals("should ignore spaces", NetworkInterfaceConstants.OK, worked);
		
		worked = other.requestUploadRights("whatever2", sampleMagicWord4);
		assertEquals("should ignore other whitespace", NetworkInterfaceConstants.OK, worked);
		
		worked = other.requestUploadRights("whatever", sampleMagicWord2);
		assertEquals("should not work magicWord inactive", NetworkInterfaceConstants.REJECTED, worked);
		
		worked = other.requestUploadRights("whatever2", nonExistentMagicWord);
		assertEquals("should be rejected", NetworkInterfaceConstants.REJECTED, worked);
		
		other.deleteAllFiles();

		TRACE_END();
	}

	public void testAllowUploadsPersistToNextSession() throws Exception
	{
		TRACE_BEGIN("testAllowUploadsPersistToNextSession");

		testServer.clearCanUploadList();
		
		String sampleId = "2345235";
		String dummyMagicWord = "elwijfjf";
		
		testServer.allowUploads(sampleId, dummyMagicWord);
		MockMartusServer other = new MockMartusServer(mockServer.getDataDirectory());
		other.setSecurity(mockServer.getSecurity());
		other.setClientListenerEnabled(true);
		other.verifyAndLoadConfigurationFiles();
		assertEquals("didn't get saved/loaded?", true, other.canClientUpload(sampleId));
		other.deleteAllFiles();

		TRACE_END();
	}

	public void testShiftToDevelopmentPortsIfRequested() throws Exception
	{
		class ServerWithSettableOS extends ServerForClients
		{
			public ServerWithSettableOS() throws Exception
			{
				super(new MockMartusServer());
			}
			
			public void deleteAllFiles() throws IOException
			{
				((MockMartusServer)coreServer).deleteAllFiles();	
			}
			
			boolean wantsDevelopmentMode()
			{
				return pretendToHaveDevelopmentFlag;
			}
			
			boolean isRunningUnderWindows()
			{
				return pretendToBeUnderWindows;
			}

			
			public boolean pretendToBeUnderWindows = false;
			public boolean pretendToHaveDevelopmentFlag = false;
		}
		
		int ports[] = {1,2};
		
		ServerWithSettableOS server = new ServerWithSettableOS();
		server.pretendToBeUnderWindows = true;
		server.pretendToHaveDevelopmentFlag = true;
		int[] windowsPorts = server.shiftToDevelopmentPortsIfRequested(ports);
		assertTrue("shifted under windows?", Arrays.equals(ports, windowsPorts));
		
		server.pretendToBeUnderWindows = false;
		server.pretendToHaveDevelopmentFlag = false;
		int[] productionLinuxPorts = server.shiftToDevelopmentPortsIfRequested(ports);
		assertTrue("shifted under production?", Arrays.equals(ports, productionLinuxPorts));
		
		server.pretendToBeUnderWindows = false;
		server.pretendToHaveDevelopmentFlag = true;
		int[] developmentLinuxPorts = server.shiftToDevelopmentPortsIfRequested(ports);
		for(int i=0; i < ports.length; ++i)
			assertEquals("didn't shift? " + i, ports[i]+9000, developmentLinuxPorts[i]);
		server.deleteAllFiles();
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

	public void testTestAccounts()	throws Exception
	{
		TRACE_BEGIN("testTestAccounts");
	
		String clientId = clientSecurity.getPublicKeyString();
		
		testServer.loadTestAccounts(createTempFile());
		assertEquals("nonexistant file should have 0 test accounts",0, testServer.getNumberOfTestAccounts());
		
		File testClient = createTempFile();
		
		UnicodeWriter writer = new UnicodeWriter(testClient);
		writer.writeln(clientId);
		writer.close();
		testServer.loadTestAccounts(testClient);
		assertEquals("1 test account should be active",1, testServer.getNumberOfTestAccounts());
		assertTrue("Tester's AccountID not found?", testServer.isTestAccount(clientId));
		
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
	
	void uploadSampleBulletin() 
	{
		mockServer.setSecurity(serverSecurity);
		mockServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString(), "silly magic word");
		mockServer.uploadBulletin(clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipString);
	}
	
	String uploadSampleDraftBulletin(Bulletin draft) throws Exception
	{
		mockServer.setSecurity(serverSecurity);
		testServer.clearCanUploadList();
		mockServer.allowUploads(clientSecurity.getPublicKeyString());
		
		String draftZipString = BulletinForTesting.saveToZipString(clientDatabase, draft, clientSecurity);
		String result = mockServer.uploadBulletin(clientSecurity.getPublicKeyString(), draft.getLocalId(), draftZipString);
		assertEquals("upload failed?", NetworkInterfaceConstants.OK, result);
		return draftZipString;
	}
	
	String uploadBulletinChunk(MartusServer server, String authorId, String localId, int totalLength, int offset, int chunkLength, String data, MartusCrypto signer) throws Exception
	{
		String stringToSign = authorId + "," + localId + "," + Integer.toString(totalLength) + "," + 
					Integer.toString(offset) + "," + Integer.toString(chunkLength) + "," + data;
		byte[] bytesToSign = stringToSign.getBytes("UTF-8");
		byte[] sigBytes = signer.createSignatureOfStream(new ByteArrayInputStream(bytesToSign));
		String signature = Base64.encode(sigBytes);
		return server.uploadBulletinChunk(authorId, localId, totalLength, offset, chunkLength, data, signature);
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
}
