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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.Vector;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import org.martus.common.ContactInfo;
import org.martus.common.HQKey;
import org.martus.common.LoggerForTesting;
import org.martus.common.MartusUtilities;
import org.martus.common.bulletin.AttachmentProxy;
import org.martus.common.bulletin.Bulletin;
import org.martus.common.bulletin.BulletinForTesting;
import org.martus.common.bulletin.BulletinLoader;
import org.martus.common.bulletin.BulletinSaver;
import org.martus.common.bulletin.BulletinZipUtilities;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MartusSecurity;
import org.martus.common.crypto.MockMartusSecurity;
import org.martus.common.crypto.MartusCrypto.MartusSignatureException;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.MockClientDatabase;
import org.martus.common.database.MockServerDatabase;
import org.martus.common.network.NetworkInterface;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.server.main.MartusServer;
import org.martus.util.Base64;
import org.martus.util.TestCaseEnhanced;
import org.martus.util.UnicodeReader;
import org.martus.util.UnicodeWriter;
import org.martus.util.Base64.InvalidBase64Exception;


public class TestMartusServer extends TestCaseEnhanced implements NetworkInterfaceConstants
{
	public TestMartusServer(String name) throws Exception
	{
		super(name);
		VERBOSE = false;

/*
 * This code creates a key pair and prints it, so you can 
 * use it to hard code in a test */
//		MartusSecurity security = new MartusSecurity(12345);
//		security.createKeyPair();
//		ByteArrayOutputStream out = new ByteArrayOutputStream();
//		security.writeKeyPair(out, "test");
//		System.out.println(Base64.encode(out.toByteArray()));

	}

	public void setUp() throws Exception
	{
		super.setUp();
		TRACE_BEGIN("setUp");

		if(clientSecurity == null)
		{
			clientSecurity = new MartusSecurity();
			clientSecurity.createKeyPair(512);
			clientAccountId = clientSecurity.getPublicKeyString();
		}
		
		if(serverSecurity == null)
		{
			serverSecurity = new MartusSecurity();
			serverSecurity.createKeyPair(512);
		}
		
		if(otherServerSecurity == null)
		{
			otherServerSecurity = new MartusSecurity();
			otherServerSecurity.createKeyPair(512);
		}

		if(hqSecurity == null)
		{
			hqSecurity = new MartusSecurity();
			hqSecurity.createKeyPair(512);
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
			b1.set(Bulletin.TAGTITLE, "Title1");
			b1.set(Bulletin.TAGPUBLICINFO, "Details1");
			b1.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails1");
			File attachment = createTempFile();
			FileOutputStream out = new FileOutputStream(attachment);
			out.write(b1AttachmentBytes);
			out.close();
			b1.addPublicAttachment(new AttachmentProxy(attachment));
			b1.addPrivateAttachment(new AttachmentProxy(attachment));
			Vector keys = new Vector();
			HQKey key1 = new HQKey(hqSecurity.getPublicKeyString(),"");
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
		
		testServer = new MockMartusServer();
		testServer.loadBannedClients();
		testServer.setSecurity(serverSecurity);
		testServer.verifyAndLoadConfigurationFiles();
		testServerInterface = new ServerSideNetworkHandler(testServer);
		serverDatabase = (MockServerDatabase)testServer.getDatabase();

		TRACE_END();
	}
	
	public void tearDown() throws Exception
	{
		TRACE_BEGIN("tearDown");

		assertEquals("isShutdownRequested", false, testServer.isShutdownRequested());
		testServer.deleteAllFiles();
		tempFile.delete();

		TRACE_END();
		super.tearDown();
	}
	
	public void testHQProxyUploadBulletin() throws Exception
	{
		TRACE_BEGIN("testHQProxyUploadBulletin");
		testServer.serverForClients.clearCanUploadList();
		String clientAccountId = clientSecurity.getPublicKeyString();
		testServer.allowUploads(clientAccountId);
		String hqAccountId = hqSecurity.getPublicKeyString();
		testServer.allowUploads(hqAccountId);

		
		Bulletin b = new Bulletin(clientSecurity);
		b.set(Bulletin.TAGTITLE, "Title1");
		b.set(Bulletin.TAGPUBLICINFO, "Details1");
		b.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails1");
		Vector hqKey = new Vector();
		HQKey key1 = new HQKey(hqAccountId,"");
		hqKey.add(key1);
		b.setAuthorizedToReadKeys(hqKey);
		b.setSealed();
		BulletinSaver.saveToClientDatabase(b, clientDatabase, true, clientSecurity);
		b = BulletinLoader.loadFromDatabase(clientDatabase, new DatabaseKey(b.getUniversalId()), clientSecurity);
		
		String draft1ZipString = BulletinForTesting.saveToZipString(clientDatabase, b, clientSecurity);
		byte[] draft1ZipBytes = Base64.decode(draft1ZipString);

		String result = testServer.putBulletinChunk(hqAccountId, clientAccountId, b.getLocalId(), draft1ZipBytes.length, 0, 
				draft1ZipBytes.length, draft1ZipString);
		assertEquals(NetworkInterfaceConstants.OK, result);

		result = testServer.putBulletinChunk(clientAccountId, clientAccountId, b.getLocalId(), draft1ZipBytes.length, 0, 
			draft1ZipBytes.length, draft1ZipString);
		assertEquals(NetworkInterfaceConstants.DUPLICATE, result);
		
		TRACE_END();
	}
	
	public void testUploadNotMyBulletin() throws Exception
	{
		TRACE_BEGIN("testUploadNotMyBulletin");
		testServer.serverForClients.clearCanUploadList();
		String authorAccountId = clientSecurity.getPublicKeyString();
		testServer.allowUploads(authorAccountId);
		String notAuthorizedAccountId = otherServerSecurity.getPublicKeyString();
		testServer.allowUploads(notAuthorizedAccountId);

		Bulletin b = new Bulletin(clientSecurity);
		b.set(Bulletin.TAGTITLE, "Title1");
		b.set(Bulletin.TAGPUBLICINFO, "Details1");
		b.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails1");
		b.setSealed();
		BulletinSaver.saveToClientDatabase(b, clientDatabase, true, clientSecurity);
		b = BulletinLoader.loadFromDatabase(clientDatabase, new DatabaseKey(b.getUniversalId()), clientSecurity);
		
		String draft1ZipString = BulletinForTesting.saveToZipString(clientDatabase, b, clientSecurity);
		byte[] draft1ZipBytes = Base64.decode(draft1ZipString);

		String result = testServer.putBulletinChunk(authorAccountId, authorAccountId, b.getLocalId(), draft1ZipBytes.length, 0, 
			draft1ZipBytes.length, draft1ZipString);
		assertEquals(NetworkInterfaceConstants.OK, result);
		
		result = testServer.putBulletinChunk(notAuthorizedAccountId, authorAccountId, b.getLocalId(), draft1ZipBytes.length, 0, 
				draft1ZipBytes.length, draft1ZipString);
		assertEquals(NetworkInterfaceConstants.NOTYOURBULLETIN, result);
		
		TRACE_END();
	}
	
	
	public void testGetNotMyBulletin() throws Exception
	{
		TRACE_BEGIN("testGetNotMyBulletin");

		testServer.security = serverSecurity;
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		testServer.uploadBulletin(clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipString);
		
		MartusSecurity	newClientSecurity = new MartusSecurity();
		newClientSecurity.createKeyPair(512);

		Vector result = getBulletinChunk(newClientSecurity, testServerInterface, b1.getAccount(), b1.getLocalId(), 0, NetworkInterfaceConstants.MAX_CHUNK_SIZE);
		assertEquals("Succeeded?  You are not the owner or the HQ", NetworkInterfaceConstants.NOTYOURBULLETIN, result.get(0));

		TRACE_END();
	}

	public void testGetHQBulletin() throws Exception
	{
		TRACE_BEGIN("testGetHQBulletin");

		testServer.security = serverSecurity;
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		testServer.uploadBulletin(clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipString);
		
		Vector result = getBulletinChunk(hqSecurity, testServerInterface, b1.getAccount(), b1.getLocalId(), 0, NetworkInterfaceConstants.MAX_CHUNK_SIZE);
		assertEquals("Failed? You are the HQ", NetworkInterfaceConstants.OK, result.get(0));

		TRACE_END();
	}

	public void testLoadHiddenPacketsList() throws Exception
	{
		String newline = "\n";
		String[] accountIds = {"silly account", "another account", "last account"};
		String[] localIds = {"local-1", "another-local", "third-local"};
		StringWriter noTrailingNewline = new StringWriter();
		noTrailingNewline.write(accountIds[0] + newline); 
		noTrailingNewline.write("  " + localIds[0] + newline);
		noTrailingNewline.write(" " + localIds[1] + newline);
		noTrailingNewline.write(accountIds[1] + newline); 
		noTrailingNewline.write(accountIds[2] + newline); 
		noTrailingNewline.write("  " + localIds[0] + "   " + localIds[2]);

		String noNewline = noTrailingNewline.toString();
		verifyLoadHiddenPacketsList(noNewline, accountIds, localIds);
		String oneNewline = noNewline + newline;
		verifyLoadHiddenPacketsList(oneNewline, accountIds, localIds);
		String twoNewlines = oneNewline + newline;
		verifyLoadHiddenPacketsList(twoNewlines, accountIds, localIds);
	}

	private void verifyLoadHiddenPacketsList(
		String isHiddenNoTrailingNewline,
		String[] accountIds,
		String[] localIds)
		throws Exception
	{
		Database db = new MockServerDatabase();
		byte[] bytes = isHiddenNoTrailingNewline.getBytes("UTF-8");
		UnicodeReader reader = new UnicodeReader(new ByteArrayInputStream(bytes));
		MartusServerUtilities.loadHiddenPacketsList(reader, db, new LoggerForTesting());
		assertTrue(db.isHidden(UniversalId.createFromAccountAndLocalId(accountIds[0], localIds[0])));
		assertTrue(db.isHidden(UniversalId.createFromAccountAndLocalId(accountIds[0], localIds[1])));
		assertTrue(db.isHidden(UniversalId.createFromAccountAndLocalId(accountIds[2], localIds[0])));
		assertTrue(db.isHidden(UniversalId.createFromAccountAndLocalId(accountIds[2], localIds[2])));
	}
	
	public void testGetNews() throws Exception
	{
		TRACE_BEGIN("testGetNews");

		Vector noNews = testServer.getNews(clientAccountId, "1.0.2", "03/03/03");
		assertEquals(2, noNews.size());
		assertEquals("ok", noNews.get(0));
		assertEquals(0, ((Vector)noNews.get(1)).size());

		testServer.serverForClients.clientsBanned.add(clientAccountId);
		Vector bannedNews = testServer.getNews(clientAccountId, "1.0.1", "01/01/03");
		assertEquals(2, bannedNews.size());
		assertEquals("ok", bannedNews.get(0));
		Vector newsItems = (Vector)bannedNews.get(1);
		assertEquals(1, newsItems.size());
		assertContains("account", (String)newsItems.get(0));
		assertContains("blocked", (String)newsItems.get(0));
		assertContains("Administrator", (String)newsItems.get(0));
		
		testServer.serverForClients.clientsBanned.remove(clientAccountId);

		TRACE_END();
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
		
		File file = testServer.serverForClients.getMagicWordsFile();
		UnicodeWriter writer = new UnicodeWriter(file);
		writer.writeln(sampleMagicWord1);
		writer.writeln(inactiveMagicWord2);
		writer.writeln(sampleMagicWordline3);
		writer.writeln(sampleMagicWordline4);
		writer.close();

		MockMartusServer other = new MockMartusServer(testServer.getDataDirectory());
		other.setClientListenerEnabled(true);
		other.verifyAndLoadConfigurationFiles();
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

		testServer.serverForClients.clearCanUploadList();
		
		String sampleId = "2345235";
		
		testServer.allowUploads(sampleId);
		MockMartusServer other = new MockMartusServer(testServer.getDataDirectory());
		other.setSecurity(testServer.security);
		other.setClientListenerEnabled(true);
		other.verifyAndLoadConfigurationFiles();
		assertEquals("didn't get saved/loaded?", true, other.canClientUpload(sampleId));
		other.deleteAllFiles();

		TRACE_END();
	}

	public void testGetServerCompliance() throws Exception
	{
		TRACE_BEGIN("testGetServerCompliance");
		String serverComplianceString = "I am compliant";
		testServer.setComplianceStatement(serverComplianceString);
		Vector compliance = testServer.getServerCompliance();
		assertEquals(2, compliance.size());
		assertEquals("ok", compliance.get(0));
		Vector result = (Vector)compliance.get(1);
		assertEquals(1, result.size());
		assertEquals(serverComplianceString, result.get(0));
		TRACE_END();
	}


	public void testGetNewsWithVersionInformation() throws Exception
	{
		TRACE_BEGIN("testGetNewsWithVersionInformation");

		final String firstNewsItem = "first news item";
		final String secondNewsItem = "second news item";
		final String thridNewsItem = "third news item";
		Vector twoNews = new Vector();
		twoNews.add(NetworkInterfaceConstants.OK);
		Vector resultNewsItems = new Vector();
		resultNewsItems.add(firstNewsItem);
		resultNewsItems.add(secondNewsItem);
		twoNews.add(resultNewsItems);
		testServer.newsResponse = twoNews;
	

		Vector noNewsForThisVersion = testServer.getNews(clientAccountId, "wrong version label" , "wrong version build date");
		assertEquals(2, noNewsForThisVersion.size());
		Vector noNewsItems = (Vector)noNewsForThisVersion.get(1);
		assertEquals(0, noNewsItems.size());
		

		String versionToUse = "2.3.4";
		testServer.newsVersionLabelToCheck = versionToUse;
		testServer.newsVersionBuildDateToCheck = "";
		Vector twoNewsItemsForThisClientsVersion = testServer.getNews(clientAccountId, versionToUse , "some version build date");
		Vector twoNewsItems = (Vector)twoNewsItemsForThisClientsVersion.get(1);
		assertEquals(2, twoNewsItems.size());
		assertEquals(firstNewsItem, twoNewsItems.get(0));
		assertEquals(secondNewsItem, twoNewsItems.get(1));


		String versionBuildDateToUse = "02/01/03";
		testServer.newsVersionLabelToCheck = "";
		testServer.newsVersionBuildDateToCheck = versionBuildDateToUse;

		Vector threeNews = new Vector();
		threeNews.add(NetworkInterfaceConstants.OK);
		resultNewsItems.add(thridNewsItem);
		threeNews.add(resultNewsItems);
		testServer.newsResponse = threeNews;

		Vector threeNewsItemsForThisClientsBuildVersion = testServer.getNews(clientAccountId, "some version label" , versionBuildDateToUse);
		Vector threeNewsItems = (Vector)threeNewsItemsForThisClientsBuildVersion.get(1);
		assertEquals(3, threeNewsItems.size());
		assertEquals(firstNewsItem, threeNewsItems.get(0));
		assertEquals(secondNewsItem, threeNewsItems.get(1));
		assertEquals(thridNewsItem, threeNewsItems.get(2));

		TRACE_END();
	}


	
	public void testLegacyApiMethodNamesNonSSL()
	{
		TRACE_BEGIN("testLegacyApiMethodNamesNonSSL");

		Method[] methods = ServerSideNetworkHandlerForNonSSL.class.getMethods();
		Vector names = new Vector();
		for(int i=0; i < methods.length; ++i)
			names.add(methods[i].getName());
		// Note: These strings are legacy and can NEVER change
		assertContains("ping", names);
		assertContains("getServerInformation", names);
		assertNotContains("requestUploadRights", names);
		assertNotContains("uploadBulletin", names);
		assertNotContains("downloadBulletin", names);
		assertNotContains("listMyBulletinSummaries", names);

		TRACE_END();
	}


	public void testLegacyApiMethodNamesSSL()
	{
		TRACE_BEGIN("testLegacyApiMethodNamesSSL");

		Method[] methods = ServerSideNetworkHandler.class.getMethods();
		Vector names = new Vector();
		for(int i=0; i < methods.length; ++i)
			names.add(methods[i].getName());

		// Note: These strings are legacy and can NEVER change
		assertNotContains("ping", names);
		assertNotContains("requestUploadRights", names);
		assertNotContains("uploadBulletinChunk", names);
		assertNotContains("downloadMyBulletinChunk", names);
		assertNotContains("listMyBulletinSummaries", names);
		assertNotContains("downloadFieldOfficeBulletinChunk", names);
		assertNotContains("listFieldOfficeBulletinSummaries", names);
		assertNotContains("listFieldOfficeAccounts", names);
		assertNotContains("downloadFieldDataPacket", names);

		TRACE_END();
	}


	public void testPing() throws Exception
	{
		TRACE_BEGIN("testPing");

		assertEquals(NetworkInterfaceConstants.VERSION, testServer.ping());

		TRACE_END();
	}
	
	public void testCreateInterimBulletinFile() throws Exception
	{
		TRACE_BEGIN("testCreateInterimBulletinFile");

		testServer.setSecurity(serverSecurity);
		File nullZipFile = createTempFileFromName("$$$MartusServerBulletinZip");
		File nullZipSignatureFile = MartusUtilities.getSignatureFileFromFile(nullZipFile);
		nullZipSignatureFile.deleteOnExit();
		assertFalse("Both zip & sig Null files verified?", testServer.verifyBulletinInterimFile(nullZipFile, nullZipSignatureFile, serverSecurity.getPublicKeyString()));
		
		File validZipFile = createTempFile();
		FileOutputStream out = new FileOutputStream(validZipFile);
		out.write(file1Bytes);
		out.close();
		assertFalse("Valid zip Null sig files verified?", testServer.verifyBulletinInterimFile(validZipFile, nullZipSignatureFile, serverSecurity.getPublicKeyString()));

		File ZipSignatureFile = MartusUtilities.createSignatureFileFromFile(validZipFile, serverSecurity);
		ZipSignatureFile.deleteOnExit();
		File nullFile = createTempFile();
		assertFalse("Null zip Valid sig file verified?", testServer.verifyBulletinInterimFile(nullFile, ZipSignatureFile, serverSecurity.getPublicKeyString()));
		
		File invalidSignatureFile = createTempFile();
		FileOutputStream outInvalidSig = new FileOutputStream(invalidSignatureFile);
		outInvalidSig.write(file2Bytes);
		outInvalidSig.close();
		assertFalse("Valid zip, invalid signature file verified?", testServer.verifyBulletinInterimFile(validZipFile, invalidSignatureFile, serverSecurity.getPublicKeyString()));

		assertTrue("Valid zip with cooresponding signature file did not verify?", testServer.verifyBulletinInterimFile(validZipFile, ZipSignatureFile, serverSecurity.getPublicKeyString()));
	

		TRACE_END();
	}
	
	public void testPutContactInfoNotEncodedBackwardCompatible() throws Exception
	{
		TRACE_BEGIN("testPutContactInfoNotEncodedBackwardCompatible");

		Vector contactInfo = new Vector();
		String clientId = clientSecurity.getPublicKeyString();
		String clientNotAuthorized = testServer.putContactInfo(clientId, contactInfo);
		assertEquals("Client has not been authorized should not accept contact info", REJECTED, clientNotAuthorized);

		testServer.serverForClients.allowUploads(clientId, null);
		String resultIncomplete = testServer.putContactInfo(clientId, contactInfo);
		assertEquals("Empty ok?", INVALID_DATA, resultIncomplete);

		contactInfo.add("bogus data");
		resultIncomplete = testServer.putContactInfo(clientId, contactInfo);
		assertEquals("Incorrect not Incomplete?", INVALID_DATA, resultIncomplete);
		
		contactInfo.clear();
		contactInfo.add(clientId);
		contactInfo.add(new Integer(1));
		contactInfo.add("Data");
		contactInfo.add("invalid Signature");
		String invalidSig = testServer.putContactInfo(clientId, contactInfo);
		assertEquals("Invalid Signature", SIG_ERROR, invalidSig);		

		contactInfo.clear();
		contactInfo.add(clientId);
		contactInfo.add(new Integer(2));
		contactInfo.add("Data");
		contactInfo.add("Data2");
		String signature = clientSecurity.createSignatureOfVectorOfStrings(contactInfo);
		contactInfo.add(signature);
		testServer.allowUploads("differentAccountID");
		String incorrectAccoutResult = testServer.putContactInfo("differentAccountID", contactInfo);
		assertEquals("Incorrect Accout ", INVALID_DATA, incorrectAccoutResult);		

		File contactFile = testServer.getContactInfoFileForAccount(clientId);
		assertFalse("Contact File already exists?", contactFile.exists());		
		String correctResult = testServer.putContactInfo(clientId, contactInfo);
		assertEquals("Correct Signature", OK, correctResult);		

		assertTrue("File Doesn't exist?", contactFile.exists());
		assertTrue("Size too small", contactFile.length() > 200);

		FileInputStream contactFileInputStream = new FileInputStream(contactFile);
		DataInputStream in = new DataInputStream(contactFileInputStream);

		String inputPublicKey = in.readUTF();
		int inputDataCount = in.readInt();
		String inputData =  in.readUTF();
		String inputData2 =  in.readUTF();
		String inputSig = in.readUTF();
		in.close();

		assertEquals("Public key doesn't match", clientId, inputPublicKey);
		assertEquals("data size not two?", 2, inputDataCount);
		assertEquals("data not correct?", "Data", inputData);
		assertEquals("data2 not correct?", "Data2", inputData2);
		assertEquals("signature doesn't match?", signature, inputSig);		

		contactFile.delete();
		contactFile.getParentFile().delete();

		testServer.serverForClients.clientsBanned.add(clientId);
		String banned = testServer.putContactInfo(clientId, contactInfo);
		assertEquals("Client is banned should not accept contact info", REJECTED, banned);
		
		TRACE_END();
	}

	public void testPutContactInfoEncoded() throws Exception
	{
		TRACE_BEGIN("testPutContactInfoEncoded");

		Vector contactInfoManual = new Vector();
		String clientId = clientSecurity.getPublicKeyString();
		String clientNotAuthorized = testServer.putContactInfo(clientId, contactInfoManual);
		assertEquals("Client has not been authorized should not accept contact info", REJECTED, clientNotAuthorized);

		testServer.serverForClients.allowUploads(clientId, null);
		String resultIncomplete = testServer.putContactInfo(clientId, contactInfoManual);
		assertEquals("Empty ok?", INVALID_DATA, resultIncomplete);

		contactInfoManual.add(NetworkInterfaceConstants.BASE_64_ENCODED);
		contactInfoManual.add("bogus data");
		resultIncomplete = testServer.putContactInfo(clientId, contactInfoManual);
		assertEquals("Incorrect not Incomplete?", INVALID_DATA, resultIncomplete);
		
		contactInfoManual.clear();
		contactInfoManual.add(NetworkInterfaceConstants.BASE_64_ENCODED);
		contactInfoManual.add(clientId);
		contactInfoManual.add(new Integer(1));
		contactInfoManual.add("Data");
		contactInfoManual.add("invalid Signature");
		String invalidSig = testServer.putContactInfo(clientId, contactInfoManual);
		assertEquals("Invalid Signature", SIG_ERROR, invalidSig);		

		String author = "Author";
		String phoneNumber = "Phone number";
		ContactInfo contactInfo = new ContactInfo(author, "org", "email", "web", phoneNumber, "address");
		MartusCrypto signer = clientSecurity;
		Vector contactInfoEncoded = contactInfo.getSignedEncodedVector(signer);
		
		testServer.allowUploads("differentAccountID");
		String incorrectAccoutResult = testServer.putContactInfo("differentAccountID", contactInfoEncoded);
		assertEquals("Incorrect Accout ", INVALID_DATA, incorrectAccoutResult);		

		File contactFile = testServer.getContactInfoFileForAccount(clientId);
		assertFalse("Contact File already exists?", contactFile.exists());		

		Vector decodedContactInfo = ContactInfo.decodeContactInfoVectorIfNecessary(contactInfoEncoded);
		String correctResultWithDecodedContactInfoSent = testServer.putContactInfo(clientId, decodedContactInfo);
		assertEquals("Encoded Config Info Correct Signature", OK, correctResultWithDecodedContactInfoSent);		
		
		String correctResultWithEncodedContactInfoSend = testServer.putContactInfo(clientId, contactInfoEncoded);
		assertEquals("Encoded Config Info Correct Signature", OK, correctResultWithEncodedContactInfoSend);		
	
		
		assertTrue("File Doesn't exist?", contactFile.exists());
		assertTrue("Size too small", contactFile.length() > 200);

		FileInputStream contactFileInputStream = new FileInputStream(contactFile);
		DataInputStream in = new DataInputStream(contactFileInputStream);

		String inputPublicKey = in.readUTF();
		int inputDataCount = in.readInt();
		String authorInputData = in.readUTF();
		in.readUTF();
		in.readUTF();
		in.readUTF();
		String phoneInputData = in.readUTF();
		in.close();

		assertEquals("Public key doesn't match", clientId, inputPublicKey);
		assertEquals("data size not six?", 6, inputDataCount);
		assertEquals("Author not correct?", author, authorInputData);
		assertEquals("Phone Number not correct?", phoneNumber, phoneInputData);

		contactFile.delete();
		contactFile.getParentFile().delete();

		testServer.serverForClients.clientsBanned.add(clientId);
		String banned = testServer.putContactInfo(clientId, contactInfoEncoded);
		assertEquals("Client is banned should not accept contact info", REJECTED, banned);
		
		TRACE_END();
	}
	
	public void testPutContactInfoThroughHandler() throws Exception
	{
		TRACE_BEGIN("testPutContactInfoThroughHandler");

		String clientId = clientSecurity.getPublicKeyString();

		Vector parameters = new Vector();
		parameters.add(clientId);
		parameters.add(new Integer(1));
		parameters.add("Data");
		String signature = clientSecurity.createSignatureOfVectorOfStrings(parameters);
		parameters.add(signature);

		String sig = clientSecurity.createSignatureOfVectorOfStrings(parameters);

		testServer.allowUploads(clientId);
		Vector result = testServerInterface.putContactInfo(clientId, parameters, sig);
		File contactFile = testServer.getContactInfoFileForAccount(clientId);
		assertEquals("Result size?", 1, result.size());
		assertEquals("Result not ok?", OK, result.get(0));

		contactFile.delete();
		contactFile.getParentFile().delete();

		TRACE_END();
	}

	public void testGetContactInfo() throws Exception
	{
		TRACE_BEGIN("testGetContactInfo");

		String author = "Author";
		String phone = "Phone number";
		MartusCrypto signer = clientSecurity;
		ContactInfo contactInfo = new ContactInfo(author, "org", "email", "web", phone, "address");
		
		Vector encodedContactInfo = contactInfo.getSignedEncodedVector(signer);
		Vector decodedContactInfo = ContactInfo.decodeContactInfoVectorIfNecessary(encodedContactInfo);
		String clientId = clientSecurity.getPublicKeyString();
		String signature = (String)encodedContactInfo.get(encodedContactInfo.size()-1);

		Vector nothingReturned = testServer.getContactInfo(clientId);
		assertEquals("No contactInfo should return null", NetworkInterfaceConstants.NOT_FOUND, nothingReturned.get(0));
		testServer.allowUploads(clientId);
		testServer.putContactInfo(clientId, encodedContactInfo);
		Vector infoReturned = testServer.getContactInfo(clientId);
		assertEquals("Should be ok", NetworkInterfaceConstants.OK, infoReturned.get(0));	
		Vector contactInfoReturnedEncoded = (Vector)infoReturned.get(1);
		Vector contactInfoReturnedDecoded = ContactInfo.decodeContactInfoVectorIfNecessary(contactInfoReturnedEncoded);
			
		assertEquals("Incorrect size Encoded",encodedContactInfo.size(), contactInfoReturnedEncoded.size());
		assertEquals("Incorrect size Decoded",decodedContactInfo.size(), contactInfoReturnedDecoded.size());
		assertEquals("Public key doesn't match", clientId, contactInfoReturnedDecoded.get(0));
		assertEquals("data size not two?", 6, ((Integer)contactInfoReturnedDecoded.get(1)).intValue());
		assertEquals("data not correct?", author, contactInfoReturnedDecoded.get(2));
		assertEquals("data2 not correct?", phone, contactInfoReturnedDecoded.get(6));
		assertEquals("signature doesn't match?", signature, contactInfoReturnedDecoded.get(8));		

		TRACE_END();
	}

	public void testGetAccountInformation() throws Exception
	{
		TRACE_BEGIN("testGetAccountInformation");

		testServer.setSecurity(serverSecurity);

		String knownAccountId = testServer.getAccountId();
		assertNotNull("null account?", knownAccountId);
		
		Vector serverInfo = testServer.getServerInformation();
		assertEquals(3, serverInfo.size());
		assertEquals(NetworkInterfaceConstants.OK, serverInfo.get(0));

		String accountId = (String)serverInfo.get(1);
		String sig = (String)serverInfo.get(2);

		assertEquals("Got wrong account back?", knownAccountId, accountId);
		verifyAccountInfo("bad test sig?", accountId, sig);

		TRACE_END();
	}
	
	public void testGetAccountInformationNoAccount() throws Exception
	{
		TRACE_BEGIN("testGetAccountInformationNoAccount");

		MockMartusServer serverWithoutKeypair = new MockMartusServer();
		serverWithoutKeypair.security.clearKeyPair();

		Vector errorInfo = serverWithoutKeypair.getServerInformation();
		assertEquals(2, errorInfo.size());
		assertEquals(NetworkInterfaceConstants.SERVER_ERROR, errorInfo.get(0));

		serverWithoutKeypair.deleteAllFiles();
		TRACE_END();
	}

	private void verifyAccountInfo(String label, String accountId, String sig) throws 
			UnsupportedEncodingException, 
			MartusSignatureException, 
			InvalidBase64Exception 
	{
		byte[] accountIdBytes = Base64.decode(accountId);

		ByteArrayInputStream in = new ByteArrayInputStream(accountIdBytes);
		byte[] expectedSig = serverSecurity.createSignatureOfStream(in);
		assertEquals(label + " encoded sig wrong?", Base64.encode(expectedSig), sig);

		ByteArrayInputStream dataInClient = new ByteArrayInputStream(accountIdBytes);
		boolean ok1 = clientSecurity.isValidSignatureOfStream(accountId, dataInClient, Base64.decode(sig));
		assertEquals(label + " client verifySig failed", true, ok1);

		ByteArrayInputStream dataInServer = new ByteArrayInputStream(accountIdBytes);
		boolean ok2 = serverSecurity.isValidSignatureOfStream(accountId, dataInServer, Base64.decode(sig));
		assertEquals(label + " server verifySig failed", true, ok2);
	}
	
	public void testUploadBulletinOneChunkOnly() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinOneChunkOnly");

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ZipBytes.length, b1ZipString, clientSecurity));

		Database db = testServer.getDatabase();
		assertNotNull("no database?", db);
		DatabaseKey key = DatabaseKey.createSealedKey(b1.getUniversalId());
		Bulletin got = BulletinLoader.loadFromDatabase(db, key, clientSecurity);
		assertEquals("id", b1.getLocalId(), got.getLocalId());

		assertEquals(NetworkInterfaceConstants.DUPLICATE, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ZipBytes.length, b1ZipString, clientSecurity));

		TRACE_END();
	}
	
	public void testUploadBulletinChunks() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinChunks");

		DatabaseKey headerKey = new DatabaseKey(b1.getUniversalId());
		DatabaseKey burKey = MartusServerUtilities.getBurKey(headerKey);
		assertFalse("BUR already exists?", serverDatabase.doesRecordExist(burKey));

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		assertTrue("BUR not created?", serverDatabase.doesRecordExist(burKey));
		TRACE_END();
	}	

	public void testUploadTwoBulletinsByChunks() throws Exception
	{
		TRACE_BEGIN("testUploadTwoBulletinsByChunks");

		String b2ZipString = BulletinForTesting.saveToZipString(clientDatabase, b2, clientSecurity);

		byte[] b2ZipBytes = Base64.decode(b2ZipString);
		byte[] b2ChunkBytes0 = new byte[100];
		byte[] b2ChunkBytes1 = new byte[b2ZipBytes.length - b2ChunkBytes0.length];
		System.arraycopy(b2ZipBytes, 0, b2ChunkBytes0, 0, b2ChunkBytes0.length);
		System.arraycopy(b2ZipBytes, b2ChunkBytes0.length, b2ChunkBytes1, 0, b2ChunkBytes1.length);
		String b2ChunkData0 = Base64.encode(b2ChunkBytes0);
		String b2ChunkData1 = Base64.encode(b2ChunkBytes1);

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b2.getLocalId(), b2ZipBytes.length, 0, b2ChunkBytes0.length, b2ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b2.getLocalId(), b2ZipBytes.length, b2ChunkBytes0.length, b2ChunkBytes1.length, b2ChunkData1, clientSecurity));

		TRACE_END();
	}

	public void testUploadBulletinChunkAtZeroRestarts() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinChunkAtZeroRestarts");

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		TRACE_END();
	}

	public void testUploadBulletinChunkTooLarge() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinChunkTooLarge");

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), NetworkInterfaceConstants.MAX_CHUNK_SIZE*2, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), NetworkInterfaceConstants.MAX_CHUNK_SIZE*2, b1ChunkBytes0.length, NetworkInterfaceConstants.MAX_CHUNK_SIZE+1, b1ChunkData1, clientSecurity));

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, NetworkInterfaceConstants.MAX_CHUNK_SIZE+1, b1ChunkData1, clientSecurity));

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));


		TRACE_END();
	}

	public void testUploadBulletinTotalSizeWrong() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinTotalSizeWrong");

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), 90, 0, 100, "", clientSecurity));

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length-1, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		TRACE_END();
	}
	
	public void testUploadBulletinChunkInvalidOffset() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinChunkInvalidOffset");

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals("1 chunk invalid offset -1",NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, -1, b1ZipBytes.length, b1ZipString, clientSecurity));
		assertEquals("1 chunk invalid offset 1",NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 1, b1ZipBytes.length, b1ZipString, clientSecurity));

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length-1, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));
			
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length+1, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		TRACE_END();
	}
	
	public void testUploadBulletinChunkDataLengthIncorrect() throws Exception
	{
		TRACE_BEGIN("testUploadBulletinChunkDataLengthIncorrect");

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length-1, b1ChunkData1, clientSecurity));
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length+1, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		TRACE_END();
	}
	
	public void testUploadChunkBadRequestSignature() throws Exception
	{
		TRACE_BEGIN("testUploadChunkBadRequestSignature");

		testServer.serverForClients.clearCanUploadList();
		String authorId = clientSecurity.getPublicKeyString();
		testServer.allowUploads(authorId);

		String localId = b1.getLocalId();
		int totalLength = b1ZipBytes.length;
		int chunkLength = b1ChunkBytes0.length;
		assertEquals("allowed bad sig?", NetworkInterfaceConstants.SIG_ERROR, testServer.uploadBulletinChunk(authorId, localId, totalLength, 0, chunkLength, b1ChunkData0, "123"));

		String stringToSign = authorId + "," + localId + "," + Integer.toString(totalLength) + "," + 
					Integer.toString(0) + "," + Integer.toString(chunkLength) + "," + b1ChunkData0;
		byte[] bytesToSign = stringToSign.getBytes("UTF-8");
		byte[] sigBytes = serverSecurity.createSignatureOfStream(new ByteArrayInputStream(bytesToSign));
		String signature = Base64.encode(sigBytes);
		assertEquals("allowed wrong sig?", NetworkInterfaceConstants.SIG_ERROR, testServer.uploadBulletinChunk(authorId, localId, totalLength, 0, chunkLength, b1ChunkData0, signature));

		TRACE_END();
	}
	
	public void testUploadChunkIOError()
	{
		//TODO implement this
		//Should return SERVER_ERROR not INVALID_DATA;
	}

	class MockDraftDatabase extends MockServerDatabase
	{
		
		public void writeRecord(DatabaseKey key, InputStream record)
			throws IOException, RecordHiddenException
		{
			if(!key.isDraft())
				throw new IOException("Invalid Status");
			super.writeRecord(key, record);
		}
	}

	class MockSealedDatabase extends MockServerDatabase
	{
		
		public void writeRecord(DatabaseKey key, InputStream record)
			throws IOException, RecordHiddenException
		{
			if(!key.isSealed())
				throw new IOException("Invalid Status");
			super.writeRecord(key, record);
		}
	}

	public void testUploadDraft() throws Exception
	{
		TRACE_BEGIN("testUploadDraft");

		Bulletin draft = new Bulletin(clientSecurity);
		draft.set(Bulletin.TAGTITLE, "Title1");
		draft.set(Bulletin.TAGPUBLICINFO, "Details1");
		draft.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails1");
		Vector keys = new Vector();
		HQKey key1 = new HQKey(hqSecurity.getPublicKeyString(), "");
		keys.add(key1);
		draft.setAuthorizedToReadKeys(keys);
		BulletinSaver.saveToClientDatabase(draft, clientDatabase, true, clientSecurity);
		draft = BulletinLoader.loadFromDatabase(clientDatabase, new DatabaseKey(draft.getUniversalId()), clientSecurity);
		String draftZipString = BulletinForTesting.saveToZipString(clientDatabase, draft, clientSecurity);
		byte[] draftZipBytes = Base64.decode(draftZipString);

		Database originalDatabase = testServer.getDatabase();
		testServer.setDatabase(new MockDraftDatabase());
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), draft.getLocalId(), draftZipBytes.length, 0, draftZipBytes.length, draftZipString, clientSecurity));
		testServer.setDatabase(originalDatabase);

		TRACE_END();
	}
	


	public void testUploadDuplicates() throws Exception
	{
		TRACE_BEGIN("testUploadDuplicates");

		Bulletin b = new Bulletin(clientSecurity);
		b.set(Bulletin.TAGTITLE, "Title1");
		b.set(Bulletin.TAGPUBLICINFO, "Details1");
		b.set(Bulletin.TAGPRIVATEINFO, "PrivateDetails1");
		File attachment = createTempFile();
		FileOutputStream out = new FileOutputStream(attachment);
		out.write(b1AttachmentBytes);
		out.close();
		b.addPublicAttachment(new AttachmentProxy(attachment));
		Vector keys = new Vector();
		HQKey key1 = new HQKey(hqSecurity.getPublicKeyString(), "");
		keys.add(key1);
		b.setAuthorizedToReadKeys(keys);
		b.setDraft();
		BulletinSaver.saveToClientDatabase(b, clientDatabase, true, clientSecurity);
		b = BulletinLoader.loadFromDatabase(clientDatabase, new DatabaseKey(b.getUniversalId()), clientSecurity);
		UniversalId attachmentUid1 = b.getPublicAttachments()[0].getUniversalId();
		DatabaseKey draftHeader1 = new DatabaseKey(b.getUniversalId());
		draftHeader1.setDraft();
		DatabaseKey attachmentKey1 = new DatabaseKey(attachmentUid1);
		attachmentKey1.setDraft();
		String draft1ZipString = BulletinForTesting.saveToZipString(clientDatabase, b, clientSecurity);
		byte[] draft1ZipBytes = Base64.decode(draft1ZipString);

		b.clearPublicAttachments();
		FileOutputStream out2 = new FileOutputStream(attachment);
		out2.write(b1AttachmentBytes);
		out2.close();
		b.addPublicAttachment(new AttachmentProxy(attachment));
		BulletinSaver.saveToClientDatabase(b, clientDatabase, true, clientSecurity);
		b = BulletinLoader.loadFromDatabase(clientDatabase, new DatabaseKey(b.getUniversalId()), clientSecurity);
		UniversalId attachmentUid2 = b.getPublicAttachments()[0].getUniversalId();
		DatabaseKey attachmentKey2 = new DatabaseKey(attachmentUid2);
		DatabaseKey draftHeader2 = new DatabaseKey(b.getUniversalId());
		draftHeader2.setDraft();
		attachmentKey2.setDraft();
		String draft2ZipString = BulletinForTesting.saveToZipString(clientDatabase,b, clientSecurity);
		byte[] draft2ZipBytes = Base64.decode(draft2ZipString);

		b.clearPublicAttachments();
		FileOutputStream out3 = new FileOutputStream(attachment);
		out3.write(b1AttachmentBytes);
		out3.close();
		b.addPublicAttachment(new AttachmentProxy(attachment));
		b.setSealed();
		BulletinSaver.saveToClientDatabase(b, clientDatabase, true, clientSecurity);
		b = BulletinLoader.loadFromDatabase(clientDatabase, new DatabaseKey(b.getUniversalId()), clientSecurity);
		UniversalId attachmentUid3 = b.getPublicAttachments()[0].getUniversalId();
		DatabaseKey attachmentKey3 = new DatabaseKey(attachmentUid3);
		DatabaseKey sealedHeader3 = new DatabaseKey(b.getUniversalId());
		sealedHeader3.setSealed();
		attachmentKey3.setSealed();
		String sealedZipString = BulletinForTesting.saveToZipString(clientDatabase, b, clientSecurity);
		byte[] sealedZipBytes = Base64.decode(sealedZipString);

		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		Database serverDatabase = testServer.getDatabase();

		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, 
			clientSecurity.getPublicKeyString(), b.getLocalId(), draft1ZipBytes.length, 0, 
			draft1ZipBytes.length, draft1ZipString, clientSecurity));

		assertEquals("Attachment 1 does not exists?", true, serverDatabase.doesRecordExist(attachmentKey1));
		assertEquals("Attachment 2 exists?", false, serverDatabase.doesRecordExist(attachmentKey2));
		assertEquals("Attachment 3 exists?", false, serverDatabase.doesRecordExist(attachmentKey3));
		assertEquals("Header 1 does not exists?", true, serverDatabase.doesRecordExist(draftHeader1));
		assertEquals("Header 2 does not exists?", true, serverDatabase.doesRecordExist(draftHeader2));
		assertEquals("Header 3 exists?", false, serverDatabase.doesRecordExist(sealedHeader3));

		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, 
			clientSecurity.getPublicKeyString(), b.getLocalId(), draft2ZipBytes.length, 0, 
			draft2ZipBytes.length, draft2ZipString, clientSecurity));

		assertEquals("Attachment 1 still exists?", false, serverDatabase.doesRecordExist(attachmentKey1));
		assertEquals("Attachment 2 does not exists?", true, serverDatabase.doesRecordExist(attachmentKey2));
		assertEquals("Attachment 3 exists?", false, serverDatabase.doesRecordExist(attachmentKey3));
		assertEquals("Header 1 does not exists?", true, serverDatabase.doesRecordExist(draftHeader1));
		assertEquals("Header 2 does not exists?", true, serverDatabase.doesRecordExist(draftHeader2));
		assertEquals("Header 3 exists?", false, serverDatabase.doesRecordExist(sealedHeader3));

		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, 
			clientSecurity.getPublicKeyString(), b.getLocalId(), sealedZipBytes.length, 0, 
			sealedZipBytes.length, sealedZipString, clientSecurity));

		assertEquals("Attachment 1 still exists?", false, serverDatabase.doesRecordExist(attachmentKey1));
		assertEquals("Attachment 2 still exists?", false, serverDatabase.doesRecordExist(attachmentKey2));
		assertEquals("Attachment 3 does not exist?", true, serverDatabase.doesRecordExist(attachmentKey3));
		assertEquals("Header 1 exists?", false, serverDatabase.doesRecordExist(draftHeader1));
		assertEquals("Header 2 exists?", false, serverDatabase.doesRecordExist(draftHeader2));
		assertEquals("Header 3 does not exists?", true, serverDatabase.doesRecordExist(sealedHeader3));

		assertEquals(NetworkInterfaceConstants.SEALED_EXISTS, uploadBulletinChunk(testServerInterface, 
			clientSecurity.getPublicKeyString(), b.getLocalId(), draft1ZipBytes.length, 0, 
			draft1ZipBytes.length, draft1ZipString, clientSecurity));

		assertEquals(NetworkInterfaceConstants.DUPLICATE, uploadBulletinChunk(testServerInterface, 
			clientSecurity.getPublicKeyString(), b.getLocalId(), sealedZipBytes.length, 0, 
			sealedZipBytes.length, sealedZipString, clientSecurity));

		TRACE_END();
	}

	public void testUploadSealedStatus() throws Exception
	{
		TRACE_BEGIN("testUploadSealedStatus");


		Database originalDatabase = testServer.getDatabase();
		testServer.setDatabase(new MockSealedDatabase());
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ZipBytes.length, b1ZipString, clientSecurity));
		testServer.setDatabase(originalDatabase);

		TRACE_END();
	}

	public void testBadlySignedBulletinUpload() throws Exception
	{
		TRACE_BEGIN("testBadlySignedBulletinUpload");

		testServer.allowUploads(clientSecurity.getPublicKeyString());
		MockMartusSecurity mockServerSecurity = MockMartusSecurity.createServer();
		mockServerSecurity.fakeSigVerifyFailure = true;
		testServer.security = mockServerSecurity;

		assertEquals("didn't verify sig?", NetworkInterfaceConstants.SIG_ERROR, testServer.uploadBulletin(clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipString));

		assertEquals("didn't verify sig for 1 chunk?", NetworkInterfaceConstants.SIG_ERROR, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ZipBytes.length, b1ZipString, clientSecurity));

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals("didn't verify sig for chunks?", NetworkInterfaceConstants.SIG_ERROR, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		testServer.security = serverSecurity;
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		TRACE_END();
	}
	
	public void testInvalidDataUpload() throws Exception
	{
		TRACE_BEGIN("testInvalidDataUpload");

		String authorClientId = clientSecurity.getPublicKeyString();
		testServer.allowUploads(authorClientId);
		String bulletinLocalId = b1.getLocalId();

		assertEquals("not base64", NetworkInterfaceConstants.INVALID_DATA, testServer.uploadBulletin(authorClientId, bulletinLocalId, "not a valid bulletin!"));

		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals("not base64 chunk", NetworkInterfaceConstants.INVALID_DATA, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, 100, "not a valid bulletin!", clientSecurity));
		assertEquals(NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, 0, b1ChunkBytes0.length, b1ChunkData0, clientSecurity));
		assertEquals(NetworkInterfaceConstants.OK, uploadBulletinChunk(testServerInterface, clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipBytes.length, b1ChunkBytes0.length, b1ChunkBytes1.length, b1ChunkData1, clientSecurity));

		assertEquals("empty fullupload", NetworkInterfaceConstants.INVALID_DATA, testServer.uploadBulletin(authorClientId, bulletinLocalId, ""));
		assertEquals("empty chunk", NetworkInterfaceConstants.CHUNK_OK, uploadBulletinChunk(testServerInterface, authorClientId, bulletinLocalId, 1, 0, 0, "", clientSecurity));
		
		ByteArrayOutputStream out2 = new ByteArrayOutputStream();
		ZipOutputStream zipWithBadEntry = new ZipOutputStream(out2);
		ZipEntry badEntry = new ZipEntry("blah");
		zipWithBadEntry.putNextEntry(badEntry);
		zipWithBadEntry.write(5);
		zipWithBadEntry.close();
		String zipWithBadEntryString = Base64.encode(out2.toByteArray());
		assertEquals("zip bad entry", NetworkInterfaceConstants.INVALID_DATA, testServer.uploadBulletin(authorClientId, "yah", zipWithBadEntryString));

		TRACE_END();
	}

	
	public void testExtractPacketsToZipStream() throws Exception
	{
		TRACE_BEGIN("testDownloadFieldOfficeBulletinChunkNotAuthorized");

		uploadSampleBulletin();
		DatabaseKey[] packetKeys = BulletinZipUtilities.getAllPacketKeys(b1.getBulletinHeaderPacket());
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		BulletinZipUtilities.extractPacketsToZipStream(b1.getAccount(), testServer.getDatabase(), packetKeys, out, serverSecurity);
		assertEquals("wrong length?", b1ZipBytes.length, out.toByteArray().length);
		
		String zipString = Base64.encode(out.toByteArray());
		assertEquals("zips different?", getZipEntryNamesAndCrcs(b1ZipString), getZipEntryNamesAndCrcs(zipString));

		TRACE_END();
	}

	String getZipEntryNamesAndCrcs(String zipString) throws 
		IOException, 
		InvalidBase64Exception, 
		ZipException 
	{
		String result = "";
		File tempFile = Base64.decodeToTempFile(zipString);
		ZipFile zip = new ZipFile(tempFile);
		Enumeration entries = zip.entries();
		while(entries.hasMoreElements())
		{
			ZipEntry entry = (ZipEntry)entries.nextElement();
			result += entry.getName();
			result += ":";
			result += new Long(entry.getCrc()).toString();
			result += ",";
		}
		return result;
	}
		
	Vector getBulletinChunk(MartusSecurity securityToUse, NetworkInterface server, String authorAccountId, String bulletinLocalId, int chunkOffset, int maxChunkSize) throws Exception
	{
		Vector parameters = new Vector();
		parameters.add(authorAccountId);
		parameters.add(bulletinLocalId);
		parameters.add(new Integer(chunkOffset));
		parameters.add(new Integer(maxChunkSize));

		String signature = securityToUse.createSignatureOfVectorOfStrings(parameters);
		return server.getBulletinChunk(securityToUse.getPublicKeyString(), parameters, signature);
	}


	public void testGetMyBulletin() throws Exception
	{
		TRACE_BEGIN("testGetHQBulletin");

		testServer.security = serverSecurity;
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		testServer.uploadBulletin(clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipString);
		
		Vector result = getBulletinChunk(clientSecurity, testServerInterface, b1.getAccount(), b1.getLocalId(), 0, NetworkInterfaceConstants.MAX_CHUNK_SIZE);
		assertEquals("Failed? I am the author", NetworkInterfaceConstants.OK, result.get(0));

		TRACE_END();
	}

	public void testListFieldOfficeDraftBulletinIds() throws Exception
	{
		TRACE_BEGIN("testListFieldOfficeDraftBulletinIds");

		testServer.security = serverSecurity;

		MartusSecurity fieldSecurity1 = clientSecurity;
		testServer.allowUploads(fieldSecurity1.getPublicKeyString());

		MartusSecurity nonFieldSecurity = MockMartusSecurity.createOtherClient();
		testServer.allowUploads(nonFieldSecurity.getPublicKeyString());

		Vector list1 = testServer.listFieldOfficeSealedBulletinIds(hqSecurity.getPublicKeyString(), fieldSecurity1.getPublicKeyString(), new Vector());
		assertNotNull("testListFieldOfficeBulletinSummaries returned null", list1);
		assertEquals("wrong length list 1", 2, list1.size());
		assertNotNull("null id1 [0] list1", list1.get(0));
		assertEquals(NetworkInterfaceConstants.OK, list1.get(0));

		Bulletin bulletinSealed = new Bulletin(clientSecurity);
		Vector keys = new Vector();
		HQKey key1 = new HQKey(hqSecurity.getPublicKeyString(),"");
		HQKey key2 = new HQKey(otherServerSecurity.getPublicKeyString(), "");
		keys.add(key1);
		keys.add(key2);
		bulletinSealed.setAuthorizedToReadKeys(keys);
		bulletinSealed.setSealed();
		bulletinSealed.setAllPrivate(true);
		BulletinSaver.saveToClientDatabase(bulletinSealed, clientDatabase, true, clientSecurity);
		testServer.uploadBulletin(clientSecurity.getPublicKeyString(), bulletinSealed.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, bulletinSealed, clientSecurity));

		Bulletin bulletinDraft = new Bulletin(clientSecurity);
		bulletinDraft.setAuthorizedToReadKeys(keys);
		bulletinDraft.setDraft();
		BulletinSaver.saveToClientDatabase(bulletinDraft, clientDatabase, true, clientSecurity);
		testServer.uploadBulletin(clientSecurity.getPublicKeyString(), bulletinDraft.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, bulletinDraft, clientSecurity));

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


	public void testListFieldOfficeAccountsErrorCondition() throws Exception
	{
		TRACE_BEGIN("testListFieldOfficeAccountsErrorCondition");

		class MyMock extends MartusSecurity
		{
			public MyMock() throws Exception
			{
			}

			public boolean signatureIsValid(byte[] sig) throws MartusSignatureException
			{
				if(!shouldFailNext)
					return super.signatureIsValid(sig);
				shouldFailNext = false;
				return false;						
			}

			public boolean isValidSignatureOfStream(PublicKey publicKey, InputStream inputStream, byte[] signature) throws
					MartusSignatureException
			{
				if(!shouldFailNext)
					return super.isValidSignatureOfStream(publicKey, inputStream, signature);
				shouldFailNext = false;
				return false;						
			}			
			boolean shouldFailNext;
		}
		MyMock myMock = new MyMock();
		testServer.security = serverSecurity;
		
		MartusSecurity fieldSecurity1 = clientSecurity;
		testServer.allowUploads(fieldSecurity1.getPublicKeyString());
		Bulletin bulletin = new Bulletin(clientSecurity);
		Vector keys = new Vector();
		HQKey key = new HQKey(hqSecurity.getPublicKeyString(), "");
		keys.add(key);
		bulletin.setAuthorizedToReadKeys(keys);
		bulletin.setSealed();
		BulletinSaver.saveToClientDatabase(bulletin, clientDatabase, true, clientSecurity);
		testServer.uploadBulletin(bulletin.getAccount(), bulletin.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, bulletin, clientSecurity));

		privateBulletin.setAuthorizedToReadKeys(keys);
		BulletinSaver.saveToClientDatabase(privateBulletin, clientDatabase, true, clientSecurity);
		testServer.uploadBulletin(privateBulletin.getAccount(), privateBulletin.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, privateBulletin, clientSecurity));

		testServer.security = myMock;
		myMock.shouldFailNext = true;
		Vector list2 = testServer.listFieldOfficeAccounts(hqSecurity.getPublicKeyString());
		assertEquals("wrong length", 2, list2.size());
		assertNotNull("null id1 [0]", list2.get(0));
		assertEquals(NetworkInterfaceConstants.SERVER_ERROR, list2.get(0));

		TRACE_END();
	}

	public void testListFieldOfficeAccounts() throws Exception
	{
		TRACE_BEGIN("testListFieldOfficeAccounts");

		testServer.security = serverSecurity;

		Database nonFieldDatabase = new MockClientDatabase();
		MartusSecurity nonFieldSecurity = MockMartusSecurity.createClient();
		testServer.allowUploads(nonFieldSecurity.getPublicKeyString());

		Bulletin b = new Bulletin(nonFieldSecurity);
		b.set(Bulletin.TAGTITLE, "Tifdfssftle3");
		b.set(Bulletin.TAGPUBLICINFO, "Detasdfsdfils1");
		b.set(Bulletin.TAGPRIVATEINFO, "PrivasdfsdfteDetails1");
		BulletinSaver.saveToClientDatabase(b, nonFieldDatabase, true, nonFieldSecurity);
		testServer.uploadBulletin(nonFieldSecurity.getPublicKeyString(), b.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, b, clientSecurity));

		Vector list1 = testServer.listFieldOfficeAccounts(hqSecurity.getPublicKeyString());
		assertNotNull("listFieldOfficeAccounts returned null", list1);
		assertEquals("wrong length", 1, list1.size());
		assertNotNull("null id1 [0]", list1.get(0));
		assertEquals(NetworkInterfaceConstants.OK, list1.get(0));

		MartusSecurity fieldSecurity1 = clientSecurity;
		testServer.allowUploads(fieldSecurity1.getPublicKeyString());
		Bulletin bulletin = new Bulletin(clientSecurity);
		Vector keys = new Vector();
		HQKey key1 = new HQKey(hqSecurity.getPublicKeyString(), "");
		HQKey key2 = new HQKey(otherServerSecurity.getPublicKeyString(), "");
		keys.add(key1);
		keys.add(key2);
		bulletin.setAuthorizedToReadKeys(keys);
		BulletinSaver.saveToClientDatabase(bulletin, clientDatabase, true, clientSecurity);
		testServer.uploadBulletin(fieldSecurity1.getPublicKeyString(), bulletin.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, bulletin, clientSecurity));

		privateBulletin.setAuthorizedToReadKeys(keys);
		BulletinSaver.saveToClientDatabase(privateBulletin, clientDatabase, true, clientSecurity);
		testServer.uploadBulletin(fieldSecurity1.getPublicKeyString(), privateBulletin.getLocalId(), BulletinForTesting.saveToZipString(clientDatabase, privateBulletin, clientSecurity));
				
		Vector list2 = testServer.listFieldOfficeAccounts(hqSecurity.getPublicKeyString());
		assertEquals("wrong length", 2, list2.size());
		assertEquals(NetworkInterfaceConstants.OK, list2.get(0));
		assertEquals("Wrong Key?", fieldSecurity1.getPublicKeyString(), list2.get(1));
		
		Vector list3 = testServer.listFieldOfficeAccounts(otherServerSecurity.getPublicKeyString());
		assertEquals("wrong length hq2", 2, list3.size());
		assertEquals(NetworkInterfaceConstants.OK, list3.get(0));
		assertEquals("Wrong Key hq2?", fieldSecurity1.getPublicKeyString(), list3.get(1));

		TRACE_END();
	}

	public void testDeleteDraftBulletinsEmptyList() throws Exception
	{
		TRACE_BEGIN("testDeleteDraftBulletinsEmptyList");

		String[] allIds = {};
		String resultAllOk = testServer.deleteDraftBulletins(clientAccountId, allIds);
		assertEquals("Empty not ok?", OK, resultAllOk);

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
		assertEquals("Result not ok?", OK, result.get(0));

		TRACE_END();
	}
		
	public void testDeleteDraftBulletins() throws Exception
	{
		TRACE_BEGIN("testDeleteDraftBulletinsThroughHandler");

		String[] allIds = uploadSampleDrafts();
		String resultAllOk = testServer.deleteDraftBulletins(clientAccountId, allIds);
		assertEquals("Good 3 not ok?", OK, resultAllOk);
		assertEquals("Didn't delete all?", 0, serverDatabase.getRecordCount());
		
		String[] twoGoodOneBad = uploadSampleDrafts();
		twoGoodOneBad[1] = "Not a valid local id";
		String resultOneBad = testServer.deleteDraftBulletins(clientAccountId, twoGoodOneBad);
		assertEquals("Two good one bad not incomplete?", INCOMPLETE, resultOneBad);
		assertEquals("Didn't delete two?", 1*databaseRecordsPerBulletin, serverDatabase.getRecordCount());
		
		uploadSampleBulletin();
		int newRecordCount = serverDatabase.getRecordCount();
		assertNotEquals("Didn't upload?", 1*databaseRecordsPerBulletin, newRecordCount);
		String[] justSealed = new String[] {b1.getLocalId()};
		testServer.deleteDraftBulletins(clientAccountId, justSealed);
		assertEquals("Sealed not ok?", OK, resultAllOk);
		assertEquals("Deleted sealed?", newRecordCount, serverDatabase.getRecordCount());

		TRACE_END();
	}

	String[] uploadSampleDrafts() throws Exception
	{
		assertEquals("db not empty?", 0, serverDatabase.getRecordCount());
		Bulletin draft1 = new Bulletin(clientSecurity);
		uploadSampleDraftBulletin(draft1);
		assertEquals("Didn't save 1?", 1*databaseRecordsPerBulletin, serverDatabase.getRecordCount());
		Bulletin draft2 = new Bulletin(clientSecurity);
		uploadSampleDraftBulletin(draft2);
		assertEquals("Didn't save 2?", 2*databaseRecordsPerBulletin, serverDatabase.getRecordCount());
		Bulletin draft3 = new Bulletin(clientSecurity);
		uploadSampleDraftBulletin(draft3);
		assertEquals("Didn't save 3?", 3*databaseRecordsPerBulletin, serverDatabase.getRecordCount());

		return new String[] {draft1.getLocalId(), draft2.getLocalId(), draft3.getLocalId()};
	}

	public void testKeyBelongsToClient()
	{
		TRACE_BEGIN("testKeyBelongsToClient");

		UniversalId uid = UniversalId.createFromAccountAndLocalId("a", "b");
		DatabaseKey key = DatabaseKey.createSealedKey(uid);
		assertEquals("doesn't belong ", false, MartusServer.keyBelongsToClient(key, "b"));
		assertEquals("belongs ", true, MartusServer.keyBelongsToClient(key, "a"));

		TRACE_END();
	}

	public void testAllowUploads() throws Exception
	{
		TRACE_BEGIN("testAllowUploads");

		File uploadsFile = testServer.serverForClients.getAllowUploadFile();

		testServer.serverForClients.clearCanUploadList();
		uploadsFile.delete();
		assertFalse("Couldn't delete uploadsok?", uploadsFile.exists());

		String clientId = "some client";
		String clientId2 = "another client";

		assertEquals("clientId default", false, testServer.canClientUpload(clientId));
		assertEquals("clientId2 default", false, testServer.canClientUpload(clientId2));
		assertEquals("empty default", false, testServer.canClientUpload(""));

		testServer.allowUploads(clientId);
		assertEquals("clientId in", true, testServer.canClientUpload(clientId));
		assertEquals("clientId2 still not in", false, testServer.canClientUpload(clientId2));
		assertEquals("empty still out", false, testServer.canClientUpload(""));

		testServer.allowUploads(clientId2);
		assertEquals("clientId2", true, testServer.canClientUpload(clientId2));
		assertEquals("clientId still", true, testServer.canClientUpload(clientId));

		uploadsFile.delete();
		assertFalse("Couldn't delete uploadsok?", uploadsFile.exists());

		testServer.deleteAllFiles();

		TRACE_END();
	}

	public void testLoadUploadList() throws Exception
	{
		TRACE_BEGIN("testLoadUploadList");

		testServer.serverForClients.clearCanUploadList();

		String clientId = "some client";
		String clientId2 = "another client";
		assertEquals("clientId default", false, testServer.canClientUpload(clientId));
		assertEquals("clientId2 default", false, testServer.canClientUpload(clientId2));

		String testFileContents = "blah blah\n" + clientId2 + "\nYeah yeah\n\n";
		testServer.serverForClients.loadCanUploadList(new BufferedReader(new StringReader(testFileContents)));
		assertEquals("clientId still out", false, testServer.canClientUpload(clientId));
		assertEquals("clientId2 now in", true, testServer.canClientUpload(clientId2));
		assertEquals("empty still out", false, testServer.canClientUpload(""));

		File uploadsFile = testServer.serverForClients.getAllowUploadFile();
		uploadsFile.delete();
		assertFalse("Couldn't delete uploadsok?", uploadsFile.exists());

		TRACE_END();
	}
	
	public void testAllowUploadsWritingToDisk() throws Exception
	{
		TRACE_BEGIN("testAllowUploadsWritingToDisk");

		testServer.serverForClients.clearCanUploadList();
		
		String clientId1 = "slidfj";
		String clientId2 = "woeiruwe";
		testServer.allowUploads(clientId1);
		testServer.allowUploads(clientId2);
		File allowUploadFile = testServer.serverForClients.getAllowUploadFile();
		long lastUpdate = allowUploadFile.lastModified();
		//Thread.sleep(1000);
		
		boolean got1 = false;
		boolean got2 = false;
		UnicodeReader reader = new UnicodeReader(allowUploadFile);
		while(true)
		{
			String line = reader.readLine();
			if(line == null)
				break;
				
			if(line.equals(clientId1))
				got1 = true;
			else if(line.equals(clientId2))
				got2 = true;
			else
				fail("unknown id found!");
		}
		reader.close();
		assertTrue("missing id1?", got1);
		assertTrue("missing id2?", got2);
		
		BufferedReader reader2 = new BufferedReader(new UnicodeReader(allowUploadFile));
		testServer.serverForClients.loadCanUploadList(reader2);
		reader2.close();
		assertEquals("reading changed the file?", lastUpdate, allowUploadFile.lastModified());
		
		TRACE_END();
	}
	
	public void testAllowUploadsAuthorizeLogWritingToDisk() throws Exception
	{
		TRACE_BEGIN("testAllowUploadsAuthorizeLogWritingToDisk");

		testServer.serverForClients.clearCanUploadList();
		
		String clientId1 = "slidfj";
		String clientId2 = "woeiruwe";
		String magicWordUsed = "magic";
		testServer.serverForClients.allowUploads(clientId1,magicWordUsed);
		testServer.serverForClients.allowUploads(clientId2,magicWordUsed);
		File authorizeLogFile = testServer.serverForClients.getAuthorizeLogFile();
		
		UnicodeReader reader = new UnicodeReader(authorizeLogFile);
		boolean got1 = false;
		boolean got2 = false;
		while(true)
		{
			String line = reader.readLine();
			if(line == null)
				break;
			if(line.indexOf(testServer.getPublicCode(clientId1))>0)
				got1 = true;
			if(line.indexOf(testServer.getPublicCode(clientId2))>0)
				got2 = true;
		}
		reader.close();
		assertTrue("missing id1?", got1);
		assertTrue("missing id2?", got2);
		
		TRACE_END();
	}
	
	public void testRequestUploadRights() throws Exception
	{
		TRACE_BEGIN("testRequestUploadRights");

		String sampleId = "384759896";
		String sampleMagicWord = "bliflfji";

		testServer.serverForClients.clearCanUploadList();
		testServer.serverForClients.addMagicWordForTesting(sampleMagicWord,null);
		
		assertEquals("any upload attemps?", 0, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		String failed = testServer.requestUploadRights(sampleId, sampleMagicWord + "x");
		assertEquals("didn't work?", NetworkInterfaceConstants.REJECTED, failed);
		assertEquals("incorrect upload attempt noted?", 1, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		String worked = testServer.requestUploadRights(sampleId, sampleMagicWord);
		assertEquals("didn't work?", NetworkInterfaceConstants.OK, worked);

		TRACE_END();
	}
	
	public void testTooManyUploadRequests() throws Exception
	{
		TRACE_BEGIN("testTooManyUploadRequests");

		String sampleId = "384759896";
		String sampleMagicWord = "bliflfji";

		testServer.serverForClients.clearCanUploadList();
		testServer.serverForClients.addMagicWordForTesting(sampleMagicWord,null);
		
		assertEquals("counter 1?", 0, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		String result = testServer.requestUploadRights(sampleId, sampleMagicWord + "x");
		assertEquals("upload request 1?", NetworkInterfaceConstants.REJECTED, result);
		assertEquals("counter 2?", 1, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		result = testServer.requestUploadRights(sampleId, sampleMagicWord);
		assertEquals("upload request 2?", NetworkInterfaceConstants.OK, result);
		
		result = testServer.requestUploadRights(sampleId, sampleMagicWord + "x");
		assertEquals("upload request 3?", NetworkInterfaceConstants.REJECTED, result);
		assertEquals("counter 3?", 2, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		result = testServer.requestUploadRights(sampleId, sampleMagicWord);
		assertEquals("upload request 4?", NetworkInterfaceConstants.SERVER_ERROR, result);
		
		result = testServer.requestUploadRights(sampleId, sampleMagicWord + "x");
		assertEquals("upload request 5?", NetworkInterfaceConstants.SERVER_ERROR, result);
		assertEquals("counter 4?", 3, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		testServer.subtractMaxFailedUploadAttemptsFromServerCounter();
		
		assertEquals("counter 5?", 1, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));
		
		result = testServer.requestUploadRights(sampleId, sampleMagicWord);
		assertEquals("upload request 6?", NetworkInterfaceConstants.OK, result);
		
		result = testServer.requestUploadRights(sampleId, sampleMagicWord+ "x");
		assertEquals("upload request 7?", NetworkInterfaceConstants.REJECTED, result);
		assertEquals("counter 6?", 2, testServer.getNumFailedUploadRequestsForIp(MockMartusServer.CLIENT_IP_ADDRESS));

		TRACE_END();
	}
	
	public void testGetAllPacketKeysSealed() throws Exception
	{
		TRACE_BEGIN("testGetAllPacketKeysSealed");

		BulletinHeaderPacket bhp = b1.getBulletinHeaderPacket();
		DatabaseKey[] keys = BulletinZipUtilities.getAllPacketKeys(bhp);
		
		assertNotNull("null ids?", keys);
		assertEquals("count?", 5, keys.length);
		boolean foundHeader = false;
		boolean foundPublicData = false;
		boolean foundPrivateData = false;
		boolean foundPublicAttachment = false;
		boolean foundPrivateAttachment = false;

		for(int i=0; i < keys.length; ++i)
		{
			assertEquals("Key " + i + " not sealed?", true, keys[i].isSealed());
			if(keys[i].getLocalId().equals(bhp.getLocalId()))
				foundHeader = true;
			if(keys[i].getLocalId().equals(bhp.getFieldDataPacketId()))
				foundPublicData = true;
			if(keys[i].getLocalId().equals(bhp.getPrivateFieldDataPacketId()))
				foundPrivateData = true;
			if(keys[i].getLocalId().equals(bhp.getPublicAttachmentIds()[0]))
				foundPublicAttachment = true;
			if(keys[i].getLocalId().equals(bhp.getPrivateAttachmentIds()[0]))
				foundPrivateAttachment = true;
		
		}		
		assertTrue("header id?", foundHeader);
		assertTrue("data id?", foundPublicData);
		assertTrue("private id?", foundPrivateData);
		assertTrue("attachment public id?", foundPublicAttachment);
		assertTrue("attachment private id?", foundPrivateAttachment);

		TRACE_END();
	}
	
	public void testGetAllPacketKeysDraft() throws Exception
	{
		TRACE_BEGIN("testGetAllPacketKeysDraft");

		BulletinHeaderPacket bhp = draft.getBulletinHeaderPacket();
		DatabaseKey[] keys = BulletinZipUtilities.getAllPacketKeys(bhp);
		
		assertNotNull("null ids?", keys);
		assertEquals("count?", 3, keys.length);
		boolean foundHeader = false;
		boolean foundPublicData = false;
		boolean foundPrivateData = false;

		for(int i=0; i < keys.length; ++i)
		{
			assertEquals("Key " + i + " not draft?", true, keys[i].isDraft());
			if(keys[i].getLocalId().equals(bhp.getLocalId()))
				foundHeader = true;
			if(keys[i].getLocalId().equals(bhp.getFieldDataPacketId()))
				foundPublicData = true;
			if(keys[i].getLocalId().equals(bhp.getPrivateFieldDataPacketId()))
				foundPrivateData = true;
		
		}		
		assertTrue("header id?", foundHeader);
		assertTrue("data id?", foundPublicData);
		assertTrue("private id?", foundPrivateData);

		TRACE_END();
	}

	public void testAuthenticateServer() throws Exception
	{
		TRACE_BEGIN("testAuthenticateServer");

		String notBase64 = "this is not base 64 ";
		String result = testServer.authenticateServer(notBase64);
		assertEquals("error not correct?", NetworkInterfaceConstants.INVALID_DATA, result);

		MockMartusServer server = new MockMartusServer();
		String base64data = Base64.encode(new byte[]{1,2,3});
		result = server.authenticateServer(base64data);
		assertEquals("did not return server error?", NetworkInterfaceConstants.SERVER_ERROR, result);

		server.setSecurity(serverSecurity);
		result = server.authenticateServer(base64data);
		byte[] signature = Base64.decode(result);
		InputStream in = new ByteArrayInputStream(Base64.decode(base64data));
		assertTrue("Invalid signature?", clientSecurity.isValidSignatureOfStream(server.security.getPublicKeyString(), in, signature));
		
		server.deleteAllFiles();

		TRACE_END();
	}
	
	public void testServerShutdown() throws Exception
	{
		TRACE_BEGIN("testServerShutdown");

		String clientId = clientSecurity.getPublicKeyString();
		String bogusStringParameter = "this is never used in this call. right?";

		ServerForClients serverForClients = testServer.serverForClients;		
		assertEquals("isShutdownRequested 1", false, testServer.isShutdownRequested());
		
		assertEquals("testServerShutdown: incrementActiveClientsCounter 1", 0, serverForClients.getNumberActiveClients() );
		
		testServer.serverForClients.clientConnectionStart();
		assertEquals("testServerShutdown: incrementActiveClientsCounter 2", 1, serverForClients.getNumberActiveClients() );
		File exitFile = testServer.getShutdownFile();
		exitFile.createNewFile();
		
		testServer.allowUploads(clientId);

		assertEquals("isShutdownRequested 2", true, testServer.isShutdownRequested());

		Vector vecResult = null; 
		String strResult = testServer.requestUploadRights(clientId, bogusStringParameter);
		assertEquals("requestUploadRights", NetworkInterfaceConstants.SERVER_DOWN, strResult );
		assertEquals("requestUploadRights", 1, serverForClients.getNumberActiveClients() );
		
		strResult = uploadBulletinChunk(testServerInterface, clientId, bogusStringParameter, 0, 0, 0, bogusStringParameter, clientSecurity);
		assertEquals("uploadBulletinChunk", NetworkInterfaceConstants.SERVER_DOWN, strResult );
		assertEquals("uploadBulletinChunk", 1, serverForClients.getNumberActiveClients() );

		strResult = testServer.putBulletinChunk(clientId, clientId, bogusStringParameter, 0, 0, 0, bogusStringParameter);
		assertEquals("putBulletinChunk", NetworkInterfaceConstants.SERVER_DOWN, strResult);
		assertEquals("putBulletinChunk", 1, serverForClients.getNumberActiveClients() );

		vecResult = testServer.getBulletinChunk(clientId, clientId, bogusStringParameter, 0, 0);
		verifyErrorResult("getBulletinChunk", vecResult, NetworkInterfaceConstants.SERVER_DOWN );
		assertEquals("getBulletinChunk", 1, serverForClients.getNumberActiveClients() );

		vecResult = testServer.getPacket(clientId, bogusStringParameter, bogusStringParameter, bogusStringParameter);
		verifyErrorResult("getPacket", vecResult, NetworkInterfaceConstants.SERVER_DOWN );
		assertEquals("getPacket", 1, serverForClients.getNumberActiveClients() );

		strResult = testServer.deleteDraftBulletins(clientId, new String[] {bogusStringParameter} );
		assertEquals("deleteDraftBulletins", NetworkInterfaceConstants.SERVER_DOWN, strResult);
		assertEquals("deleteDraftBulletins", 1, serverForClients.getNumberActiveClients() );

		strResult = testServer.putContactInfo(clientId, new Vector() );
		assertEquals("putContactInfo", NetworkInterfaceConstants.SERVER_DOWN, strResult);		
		assertEquals("putContactInfo", 1, serverForClients.getNumberActiveClients() );

		vecResult = testServer.listFieldOfficeAccounts(clientId);
		verifyErrorResult("listFieldOfficeAccounts", vecResult, NetworkInterfaceConstants.SERVER_DOWN );
		assertEquals("listFieldOfficeAccounts", 1, serverForClients.getNumberActiveClients() );

		exitFile.delete();

		assertEquals("isShutdownRequested 3", false, testServer.isShutdownRequested());
				
		testServer.serverForClients.clientConnectionExit();
		assertEquals("testServerShutdown: clientCount", 0, serverForClients.getNumberActiveClients() );	

		TRACE_END();
	}
	
	public void testServerConnectionDuringShutdown() throws Exception
	{
		TRACE_BEGIN("testServerConnectionDuringShutdown");

		Vector reply;
		
		testServer.serverForClients.clientConnectionStart();
		File exitFile = testServer.getShutdownFile();
		exitFile.createNewFile();
		
		reply = testServer.getServerInformation();
		assertEquals("getServerInformation", NetworkInterfaceConstants.SERVER_DOWN, reply.get(0) );

		exitFile.delete();
		testServer.serverForClients.clientConnectionExit();

		TRACE_END();
	}
	
	void verifyErrorResult(String label, Vector vector, String expected )
	{
		assertEquals( label + " error size not 1?", 1, vector.size());
		assertEquals( label + " error wrong result code", expected, vector.get(0));
	}

	void uploadSampleBulletin() 
	{
		testServer.security = serverSecurity;
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		testServer.uploadBulletin(clientSecurity.getPublicKeyString(), b1.getLocalId(), b1ZipString);
	}
	
	String uploadSampleDraftBulletin(Bulletin draft) throws Exception
	{
		testServer.security = serverSecurity;
		testServer.serverForClients.clearCanUploadList();
		testServer.allowUploads(clientSecurity.getPublicKeyString());
		
		String draftZipString = BulletinForTesting.saveToZipString(clientDatabase, draft, clientSecurity);
		String result = testServer.uploadBulletin(clientSecurity.getPublicKeyString(), draft.getLocalId(), draftZipString);
		assertEquals("upload failed?", OK, result);
		return draftZipString;
	}
	
	String uploadBulletinChunk(NetworkInterface server, String authorId, String localId, int totalLength, int offset, int chunkLength, String data, MartusCrypto signer) throws Exception
	{
		String stringToSign = authorId + "," + localId + "," + Integer.toString(totalLength) + "," + 
					Integer.toString(offset) + "," + Integer.toString(chunkLength) + "," + data;
		byte[] bytesToSign = stringToSign.getBytes("UTF-8");
		byte[] sigBytes = signer.createSignatureOfStream(new ByteArrayInputStream(bytesToSign));
		String signature = Base64.encode(sigBytes);
		return testServer.uploadBulletinChunk(authorId, localId, totalLength, offset, chunkLength, data, signature);
	}
	
	static File tempFile;
	static Bulletin b1;
	static String b1ZipString;
	static byte[] b1ZipBytes;
	static byte[] b1ChunkBytes0;
	static byte[] b1ChunkBytes1;
	static String b1ChunkData0;
	static String b1ChunkData1;

	static Bulletin b2;
	static Bulletin privateBulletin;

	static Bulletin draft;

	static final int databaseRecordsPerBulletin = 4;
	static MartusSecurity clientSecurity;
	static String clientAccountId;
	static MartusSecurity serverSecurity;
	static MartusSecurity otherServerSecurity;
	static MartusSecurity hqSecurity;
	static MockClientDatabase clientDatabase;

	final static byte[] b1AttachmentBytes = {1,2,3,4,4,3,2,1};
	final static byte[] file1Bytes = {1,2,3,4,4,3,2,1};
	final static byte[] file2Bytes = {1,2,3,4,4,3,2,1,0};
	
	MockMartusServer testServer;
	NetworkInterface testServerInterface;
	MockServerDatabase serverDatabase;
	
}
