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

package org.martus.server.formirroring;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.Vector;

import org.martus.common.LoggerToNull;
import org.martus.common.bulletin.Bulletin;
import org.martus.common.bulletin.BulletinZipUtilities;
import org.martus.common.bulletinstore.BulletinStore;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MockMartusSecurity;
import org.martus.common.crypto.MartusCrypto.CreateDigestException;
import org.martus.common.crypto.MartusCrypto.CryptoException;
import org.martus.common.crypto.MartusCrypto.MartusSignatureException;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.MockDatabase;
import org.martus.common.database.ReadableDatabase;
import org.martus.common.database.Database.RecordHiddenException;
import org.martus.common.network.NetworkResponse;
import org.martus.common.network.mirroring.CallerSideMirroringGateway;
import org.martus.common.network.mirroring.MirroringInterface;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.packet.Packet.InvalidPacketException;
import org.martus.common.packet.Packet.SignatureVerificationException;
import org.martus.common.test.MockBulletinStore;
import org.martus.common.test.UniversalIdForTesting;
import org.martus.server.forclients.MockMartusServer;
import org.martus.server.main.BulletinUploadRecord;
import org.martus.server.main.ServerBulletinStore;
import org.martus.util.Base64;
import org.martus.util.TestCaseEnhanced;
import org.martus.util.inputstreamwithseek.InputStreamWithSeek;


public class TestMirroringRetriever extends TestCaseEnhanced
{
	public TestMirroringRetriever(String name)
	{
		super(name);
	}
	
	public void setUp() throws Exception
	{
		super.setUp();
		server = new MockMartusServer();
		MartusCrypto security = server.getSecurity();
		
		supplier = new FakeServerSupplier();
		supplier.authorizedCaller = security.getPublicKeyString();

		handler = new SupplierSideMirroringHandler(supplier, security);
		realGateway = new CallerSideMirroringGateway(handler);
		LoggerToNull logger = new LoggerToNull();
		realRetriever = new MirroringRetriever(server.getStore(), realGateway, "Dummy IP", logger);
		
	}
	
	public void tearDown() throws Exception
	{
		super.tearDown();
		server.deleteAllFiles();
	}
	
	public void testGetNextItemToRetrieve() throws Exception
	{
		assertNull("item available right after constructor?", realRetriever.getNextItemToRetrieve());
		Vector items = new Vector();
		for(int i=0; i < 3; ++i)
		{
			UniversalId uid = UniversalId.createDummyUniversalId();
			BulletinMirroringInformation info = new BulletinMirroringInformation(uid);
			items.add(info);
			realRetriever.itemsToRetrieve.add(info);
		}

		for(int i=0; i < items.size(); ++i)
			assertEquals("wrong " + i + "?", items.get(i), realRetriever.getNextItemToRetrieve());

		assertNull("uid right after emptied?", realRetriever.getNextItemToRetrieve());
		assertNull("uid again after emptied?", realRetriever.getNextItemToRetrieve());
	}
	
	public void testGetNextAccountToRetrieve() throws Exception
	{
		assertNull("account right after constructor?", realRetriever.getNextAccountToRetrieve());
		Vector accounts = new Vector();
		for(int i=0; i < 3; ++i)
			accounts.add(Integer.toString(i));
			
		realRetriever.accountsToRetrieve.addAll(accounts);
		for (int i = 0; i < accounts.size(); i++)
			assertEquals("wrong " + i + "?", accounts.get(i), realRetriever.getNextAccountToRetrieve());

		assertNull("account right after emptied?", realRetriever.getNextAccountToRetrieve());
		assertNull("account again after emptied?", realRetriever.getNextAccountToRetrieve());
	}
	
	public void testGetNextAccountSkipsIfNothingRecent() throws Exception
	{
		supplier.addAccountToMirror("Test account");
		realRetriever.shouldSleepNextCycle = true;
		realRetriever.getNextAccountToRetrieve();
		assertTrue("Should have set sleepUntil", realRetriever.sleepUntil > System.currentTimeMillis() + 2000);
		
		realRetriever.sleepUntil = System.currentTimeMillis() + 5000;
		assertNull("should have slept1", realRetriever.getNextAccountToRetrieve());
		assertNull("should have slept2", realRetriever.getNextAccountToRetrieve());
	}
	
	public void testRetrieveOneBulletin() throws Exception
	{
		supplier.returnResultTag = MirroringInterface.RESULT_OK;
		
		UniversalId uid = UniversalId.createDummyUniversalId();
		supplier.addZipData(uid, Base64.encode("some text"));
		File tempFile = createTempFile();
		tempFile.deleteOnExit();
		
		realRetriever.retrieveOneBulletin(tempFile, uid);
		assertEquals(uid.getAccountId(), supplier.gotAccount);
		assertEquals(uid.getLocalId(), supplier.gotLocalId);

		int expectedLength = Base64.decode((String)supplier.zipData.get(uid)).length;
		assertEquals("file wrong length?", expectedLength, tempFile.length());
	}
	
	public void testTickWithNewMirroringServer() throws Exception
	{
		TestCallerSideMirroringGateway newGateway = new TestCallerSideMirroringGateway(handler);
		LoggerToNull logger = new LoggerToNull();
		MirroringRetriever newMirroringRetriever = new MirroringRetriever(server.getStore(), newGateway, "Dummy IP", logger);

		internalTestTick(newMirroringRetriever);
		assertTrue(newGateway.listAvailableIdsForMirroringCalled);
		assertFalse(newGateway.listBulletinsForMirroringCalled);
	}

	public void testTickWithOldMirroringServer() throws Exception
	{
		SupplierSideMirroringHandler oldHandler = new OldSupplierSideMirroringHandler(supplier, server.getSecurity());
		TestCallerSideMirroringGateway oldGateway = new TestCallerSideMirroringGateway(oldHandler);
		LoggerToNull logger = new LoggerToNull();

		MirroringRetriever mirroringRetriever = new MirroringRetriever(server.getStore(), oldGateway, "Dummy IP", logger);
		internalTestTick(mirroringRetriever);
		assertTrue(oldGateway.listBulletinsForMirroringCalled);
	}
	
	class TestCallerSideMirroringGateway extends CallerSideMirroringGateway
	{
		public TestCallerSideMirroringGateway(MirroringInterface handlerToUse)
		{
			super(handlerToUse);
		}

		public NetworkResponse listAvailableIdsForMirroring(MartusCrypto signer, String authorAccountId) throws MartusSignatureException
		{
			listAvailableIdsForMirroringCalled = true;
			return super.listAvailableIdsForMirroring(signer, authorAccountId);
		}

		public NetworkResponse listBulletinsForMirroring(MartusCrypto signer, String authorAccountId) throws MartusSignatureException
		{
			listBulletinsForMirroringCalled = true;
			return super.listBulletinsForMirroring(signer, authorAccountId);
		}
		
		public boolean listAvailableIdsForMirroringCalled;
		public boolean listBulletinsForMirroringCalled;
	}
	
	class OldSupplierSideMirroringHandler extends SupplierSideMirroringHandler
	{
		public OldSupplierSideMirroringHandler(ServerSupplierInterface supplierToUse, MartusCrypto verifierToUse)
		{
			super(supplierToUse, verifierToUse);
		}

		int extractCommand(Object possibleCommand)
		{
			String cmdString = (String)possibleCommand;
			if(cmdString.equals(CMD_MIRRORING_LIST_AVAILABLE_IDS))
				return cmdUnknown;
			return super.extractCommand(possibleCommand);
		}
	}


	private void internalTestTick(MirroringRetriever mirroringRetriever) throws Exception, IOException, CryptoException, CreateDigestException, RecordHiddenException, InvalidPacketException, SignatureVerificationException
	{
		assertFalse("initial shouldsleep wrong?", mirroringRetriever.shouldSleepNextCycle);
		// get account list (empty)
		mirroringRetriever.processNextBulletin();
		assertNull("tick asked for account?", supplier.gotAccount);
		assertNull("tick asked for id?", supplier.gotLocalId);
		assertTrue("not ready to sleep?", mirroringRetriever.shouldSleepNextCycle);
		
		BulletinStore serverStore = new MockBulletinStore(this);
		MockDatabase db = (MockDatabase)serverStore.getDatabase();
		MartusCrypto otherServerSecurity = MockMartusSecurity.createOtherServer();

		MartusCrypto clientSecurity = MockMartusSecurity.createClient();
		supplier.addAccountToMirror(clientSecurity.getPublicKeyString());
		Vector bulletins = new Vector();
		for(int i=0; i < 3; ++i)
		{
			Bulletin b = new Bulletin(clientSecurity);
			b.setSealed();
			bulletins.add(b);
			DatabaseKey key = DatabaseKey.createSealedKey(b.getUniversalId());
			serverStore.saveBulletinForTesting(b);

			String bur = BulletinUploadRecord.createBulletinUploadRecord(b.getLocalId(), otherServerSecurity);
			supplier.addBur(b.getUniversalId(), bur);
			supplier.addZipData(b.getUniversalId(), getZipString(db, b, clientSecurity));
			BulletinUploadRecord.writeSpecificBurToDatabase(db, b.getBulletinHeaderPacket(), bur);
			assertEquals("after write bur" + i, (i+1)*databaseRecordsPerBulletin, db.getRecordCount());

			InputStreamWithSeek in = db.openInputStream(key, otherServerSecurity);
			byte[] sigBytes = BulletinHeaderPacket.verifyPacketSignature(in, otherServerSecurity);
			in.close();
			String sigString = Base64.encode(sigBytes);
			supplier.addAvailableIdsToMirror(db, key, sigString);
			supplier.addBulletinToMirror(key, sigString);

		}

		ServerBulletinStore store = server.getStore();
		mirroringRetriever.shouldSleepNextCycle = false;
		assertEquals("before tick a", 0, store.getBulletinCount());
		// get account list
		mirroringRetriever.processNextBulletin();
		assertNull("tick a asked for account?", supplier.gotAccount);
		assertNull("tick a asked for id?", supplier.gotLocalId);
		assertEquals("after tick a", 0, store.getBulletinCount());
		//get bulletin list
		mirroringRetriever.processNextBulletin();
		assertNull("tick b asked for account?", supplier.gotAccount);
		assertNull("tick b asked for id?", supplier.gotLocalId);
		assertEquals("after tick b", 0, store.getBulletinCount());

		assertTrue("shouldsleep defaulting false?", mirroringRetriever.shouldSleepNextCycle);
		supplier.returnResultTag = MirroringInterface.RESULT_OK;
		Vector bulletinLocalIdsRetrieved = new Vector();
		for(int goodTick = 0; goodTick < 3; ++goodTick)
		{
			mirroringRetriever.processNextBulletin();
			assertEquals("tick " + goodTick + " wrong account?", clientSecurity.getPublicKeyString(), supplier.gotAccount);
			bulletinLocalIdsRetrieved.add(supplier.gotLocalId);
			assertEquals("after tick " + goodTick, (goodTick+1), store.getBulletinCount());
			assertFalse("shouldsleep " + goodTick + " wrong?", mirroringRetriever.shouldSleepNextCycle);
		}
		
		for(int i = 0; i < 3; ++i)
		{
			assertContains(((Bulletin)bulletins.get(i)).getLocalId(), bulletinLocalIdsRetrieved);
		}	
		
		mirroringRetriever.processNextBulletin();
		assertEquals("after extra tick", 3, store.getBulletinCount());
		assertEquals("extra tick got uids?", 0, mirroringRetriever.itemsToRetrieve.size());
		assertTrue("after extra tick shouldsleep false?", mirroringRetriever.shouldSleepNextCycle);
		mirroringRetriever.processNextBulletin();
		assertEquals("after extra tick2", 3, store.getBulletinCount());
		assertEquals("extra tick2 got uids?", 0, mirroringRetriever.itemsToRetrieve.size());
	}
	
	public void testListPacketsWeWant() throws Exception
	{
		MartusCrypto clientSecurity = MockMartusSecurity.createClient();
		String accountId = clientSecurity.getPublicKeyString();
		Vector infos = new Vector();

		UniversalId hiddenUid1 = addNewUid(infos, accountId);
		UniversalId visibleUid = addNewUid(infos, accountId);
		UniversalId hiddenUid2 = addNewUid(infos, accountId);
		
		Database db = server.getWriteableDatabase();
		db.hide(hiddenUid1);
		db.hide(hiddenUid2);
		
		Vector result = realRetriever.listOnlyPacketsThatWeWantUsingLocalIds(accountId, infos);
		assertEquals("Didn't remove hidden?", 1, result.size());
		assertEquals("Wrong info?", visibleUid, ((BulletinMirroringInformation)result.get(0)).getUid());
	}

	private UniversalId addNewUid(Vector infos, String accountId)
	{
		UniversalId newUid = UniversalIdForTesting.createFromAccountAndPrefix(accountId, "H");
		Vector newInfo = new Vector();
		newInfo.add(newUid.getLocalId());
		infos.add(newInfo);
		return newUid;
	}
	
	private String getZipString(ReadableDatabase dbToExportFrom, Bulletin b, MartusCrypto signer) throws Exception
	{
		String accountId = b.getAccount();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DatabaseKey[] packetKeys = BulletinZipUtilities.getAllPacketKeys(b.getBulletinHeaderPacket());
		BulletinZipUtilities.extractPacketsToZipStream(accountId, dbToExportFrom, packetKeys, out, signer);
		String zipString = Base64.encode(out.toByteArray());
		return zipString;
	}

	final static int databaseRecordsPerBulletin = 4;

	MockMartusServer server;
	FakeServerSupplier supplier;
	SupplierSideMirroringHandler handler;
	CallerSideMirroringGateway realGateway;
	MirroringRetriever realRetriever;
}
