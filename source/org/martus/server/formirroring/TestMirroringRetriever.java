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
import java.util.Vector;

import org.martus.common.BulletinStore;
import org.martus.common.LoggerForTesting;
import org.martus.common.bulletin.Bulletin;
import org.martus.common.bulletin.BulletinZipUtilities;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MockMartusSecurity;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.MockServerDatabase;
import org.martus.common.network.mirroring.CallerSideMirroringGateway;
import org.martus.common.network.mirroring.MirroringInterface;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.common.test.UniversalIdForTesting;
import org.martus.server.forclients.MockMartusServer;
import org.martus.server.main.BulletinUploadRecord;
import org.martus.server.main.ServerBulletinStore;
import org.martus.util.Base64;
import org.martus.util.InputStreamWithSeek;
import org.martus.util.TestCaseEnhanced;

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
		LoggerForTesting logger = new LoggerForTesting();
		realRetriever = new MirroringRetriever(server.getStore(), realGateway, "Dummy IP", logger);
		
	}
	
	public void testGetNextUidToRetrieve() throws Exception
	{
		assertNull("uid right after constructor?", realRetriever.getNextUidToRetrieve());
		Vector uids = new Vector();
		for(int i=0; i < 3; ++i)
		{
			UniversalId uid = UniversalId.createDummyUniversalId(); 
			uids.add(uid);
			realRetriever.uidsToRetrieve.add(uid);
		}

		for(int i=0; i < uids.size(); ++i)
			assertEquals("wrong " + i + "?", uids.get(i), realRetriever.getNextUidToRetrieve());

		assertNull("uid right after emptied?", realRetriever.getNextUidToRetrieve());
		assertNull("uid again after emptied?", realRetriever.getNextUidToRetrieve());
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
		File tempFile = createTempFile();
		tempFile.deleteOnExit();
		realRetriever.retrieveOneBulletin(tempFile, uid);
		assertEquals(uid.getAccountId(), supplier.gotAccount);
		assertEquals(uid.getLocalId(), supplier.gotLocalId);

		int expectedLength = Base64.decode(supplier.returnZipData).length;
		assertEquals("file wrong length?", expectedLength, tempFile.length());
	}
	
	public void testTick() throws Exception
	{
		assertFalse("initial shouldsleep wrong?", realRetriever.shouldSleepNextCycle);
		// get account list (empty)
		realRetriever.retrieveNextBulletin();
		assertNull("tick asked for account?", supplier.gotAccount);
		assertNull("tick asked for id?", supplier.gotLocalId);
		assertTrue("not ready to sleep?", realRetriever.shouldSleepNextCycle);
		
		MockServerDatabase fakeDatabase = new MockServerDatabase();
		MartusCrypto otherServerSecurity = MockMartusSecurity.createOtherServer();

		MartusCrypto clientSecurity = MockMartusSecurity.createClient();
		supplier.addAccountToMirror(clientSecurity.getPublicKeyString());
		Vector bulletins = new Vector();
		String[] burs = new String[3];
		for(int i=0; i < 3; ++i)
		{
			Bulletin b = new Bulletin(clientSecurity);
			b.setSealed();
			bulletins.add(b);
			DatabaseKey key = DatabaseKey.createSealedKey(b.getUniversalId());
			BulletinStore.saveToClientDatabase(b, fakeDatabase, false, clientSecurity);

			String bur = BulletinUploadRecord.createBulletinUploadRecord(b.getLocalId(), otherServerSecurity);
			burs[i] = bur;
			BulletinUploadRecord.writeSpecificBurToDatabase(fakeDatabase, b.getBulletinHeaderPacket(), bur);
			assertEquals("after write bur" + i, (i+1)*databaseRecordsPerBulletin, fakeDatabase.getRecordCount());

			InputStreamWithSeek in = fakeDatabase.openInputStream(key, otherServerSecurity);
			byte[] sigBytes = BulletinHeaderPacket.verifyPacketSignature(in, otherServerSecurity);
			in.close();
			String sigString = Base64.encode(sigBytes);
			supplier.addBulletinToMirror(key, sigString);
		}

		ServerBulletinStore store = server.getStore();
		realRetriever.shouldSleepNextCycle = false;
		assertEquals("before tick a", 0, store.getBulletinCount());
		// get account list
		realRetriever.retrieveNextBulletin();
		assertNull("tick a asked for account?", supplier.gotAccount);
		assertNull("tick a asked for id?", supplier.gotLocalId);
		assertEquals("after tick a", 0, store.getBulletinCount());
		//get bulletin list
		realRetriever.retrieveNextBulletin();
		assertNull("tick b asked for account?", supplier.gotAccount);
		assertNull("tick b asked for id?", supplier.gotLocalId);
		assertEquals("after tick b", 0, store.getBulletinCount());

		assertTrue("shouldsleep defaulting false?", realRetriever.shouldSleepNextCycle);
		supplier.returnResultTag = MirroringInterface.RESULT_OK;
		for(int goodTick = 0; goodTick < 3; ++goodTick)
		{
			Bulletin expectedBulletin = (Bulletin)bulletins.get(goodTick);
			supplier.returnZipData = getZipString(fakeDatabase, expectedBulletin, clientSecurity);
			supplier.addBur(expectedBulletin.getAccount(), expectedBulletin.getLocalId(), burs[goodTick]);
			realRetriever.retrieveNextBulletin();
			assertEquals("tick " + goodTick + " wrong account?", clientSecurity.getPublicKeyString(), supplier.gotAccount);
			assertEquals("tick " + goodTick + " wrong id?", ((Bulletin)bulletins.get(goodTick)).getLocalId(), supplier.gotLocalId);
			assertEquals("after tick " + goodTick, (goodTick+1), store.getBulletinCount());
			assertFalse("shouldsleep " + goodTick + " wrong?", realRetriever.shouldSleepNextCycle);
		}
		realRetriever.retrieveNextBulletin();
		assertEquals("after extra tick", 3, store.getBulletinCount());
		assertEquals("extra tick got uids?", 0, realRetriever.uidsToRetrieve.size());
		assertTrue("after extra tick shouldsleep false?", realRetriever.shouldSleepNextCycle);
		realRetriever.retrieveNextBulletin();
		assertEquals("after extra tick2", 3, store.getBulletinCount());
		assertEquals("extra tick2 got uids?", 0, realRetriever.uidsToRetrieve.size());
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
		
		Vector result = realRetriever.listOnlyPacketsThatWeWant(accountId, infos);
		assertEquals("Didn't remove hidden?", 1, result.size());
		assertEquals("Wrong info?", visibleUid, result.get(0));
	}

	private UniversalId addNewUid(Vector infos, String accountId)
	{
		UniversalId newUid = UniversalIdForTesting.createFromAccountAndPrefix(accountId, "H");
		Vector newInfo = new Vector();
		newInfo.add(newUid.getLocalId());
		infos.add(newInfo);
		return newUid;
	}
	
	private String getZipString(Database dbToExportFrom, Bulletin b, MartusCrypto signer) throws Exception
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
