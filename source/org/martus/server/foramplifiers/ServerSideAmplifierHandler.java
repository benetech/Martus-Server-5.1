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

package org.martus.server.foramplifiers;

import java.util.Vector;

import org.martus.common.AmplifierNetworkInterface;
import org.martus.common.BulletinStore;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.ReadableDatabase;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.server.main.BulletinUploadRecord;

public class ServerSideAmplifierHandler implements AmplifierNetworkInterface
{
	public ServerSideAmplifierHandler(ServerForAmplifiers serverToUse)
	{
		server = serverToUse;
	}
	
	/// Begin Interface //
	
	public Vector getAccountIds(String myAccountId, Vector parameters, String signature)
	{
		log("getAccountIds: " + MartusCrypto.formatAccountIdForLog(myAccountId));
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		class AccountVisitor implements Database.AccountVisitor
		{
			AccountVisitor()
			{
				accounts = new Vector();
			}
	
			public void visit(String accountString)
			{
				if(!server.canAccountBeAmplified(accountString))
					return;

				LocallIdOfPublicBulletinsCollector collector = new LocallIdOfPublicBulletinsCollector();
				ReadableDatabase db = server.getDatabase();
				db.visitAllRecordsForAccount(collector, accountString);
				if(collector.infos.size() > 0 && ! accounts.contains(accountString))
					accounts.add(accountString);
			}
	
			public Vector getAccounts()
			{
				return accounts;
			}
			Vector accounts;
		}
		
		Vector result = checkSignature(myAccountId, parameters, signature);
		if(result != null)
			return result;
		result = new Vector();
		
		AccountVisitor visitor = new AccountVisitor();
		server.getDatabase().visitAllAccounts(visitor);
		
		result.add(NetworkInterfaceConstants.OK);
		result.add(visitor.getAccounts());
		log("getAccountIds: returned " + visitor.getAccounts().size() + " accounts");
		return result;
	}

	public Vector getContactInfo(String myAccountId, Vector parameters, String signature)
	{
		log("getContactInfo: amp: " + MartusCrypto.formatAccountIdForLog(myAccountId));
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		Vector result = checkSignature(myAccountId, parameters, signature);
		if(result != null)
			return result;
		result = new Vector();
		
		if(parameters.size() != 1)
		{
			result.add(NetworkInterfaceConstants.INCOMPLETE);
			log("getAccountContactInfo incomplete request");
			return result;
		}
		
		String accountIdToRetrieve = (String)parameters.get(0);
		result = server.getContactInfo(accountIdToRetrieve);
		String resultString = ""; 
		if(((String)result.get(0)).equals(NetworkInterfaceConstants.OK))
			resultString = "some";
		else
			resultString = "none";
		
		log("getContactInfo: account: " + MartusCrypto.formatAccountIdForLog(accountIdToRetrieve) + " had " + resultString);
		return result;
	}
	
	public Vector getPublicBulletinLocalIds(String myAccountId, Vector parameters, String signature)
	{
		log("getPublicBulletinLocalIds: amp: " + MartusCrypto.formatAccountIdForLog(myAccountId));
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		Vector result = checkSignature(myAccountId, parameters, signature);
		if(result != null)
			return result;
		result = new Vector();
		
		String accountString = (String) parameters.get(0);

		LocallIdOfPublicBulletinsCollector collector = new LocallIdOfPublicBulletinsCollector();
		ReadableDatabase db = server.getDatabase();
		db.visitAllRecordsForAccount(collector, accountString);
		
		result.add(NetworkInterfaceConstants.OK);
		result.add(collector.infos);
		log("getPublicBulletinLocalIds: account:"+ MartusCrypto.formatAccountIdForLog(accountString) + " = "+collector.infos.size());
		
		return result;
	}
	
	public Vector getAmplifierBulletinChunk(String myAccountId, Vector parameters, String signature)
	{
		log("getAmplifierBulletinChunk: " + MartusCrypto.formatAccountIdForLog(myAccountId));
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		Vector result = checkSignature(myAccountId, parameters, signature);
		if(result != null)
			return result;
		result = new Vector();
		
		int index = 0;
		String authorAccountId = (String)parameters.get(index++);
		String bulletinLocalId= (String)parameters.get(index++);
		int chunkOffset = ((Integer)parameters.get(index++)).intValue();
		int maxChunkSize = ((Integer)parameters.get(index++)).intValue();

		Vector legacyResult = server.getBulletinChunk(myAccountId, authorAccountId, bulletinLocalId, 
				chunkOffset, maxChunkSize);
		String resultCode = (String)legacyResult.get(0);
		legacyResult.remove(0);
				
		result.add(resultCode);
		result.add(legacyResult);
		
		return result;
	}
	
	/// End Interface //
	
	class LocallIdOfPublicBulletinsCollector implements Database.PacketVisitor
	{
		public void visit(DatabaseKey key)
		{
			try
			{
				if(! key.getLocalId().startsWith("B-") )
					return;
				if(key.isDraft())
					return;
				
				DatabaseKey burKey = BulletinUploadRecord.getBurKey(key);
				MartusCrypto security = server.getSecurity();
				ReadableDatabase db = server.getDatabase();
				String burInDatabase = db.readRecord(burKey, security);
				if(burInDatabase == null)
				{	
					log("Error: Missing BUR packet for bulletin:" +key.getUniversalId());
					return;
				}
				
				if(!BulletinUploadRecord.wasBurCreatedByThisCrypto(burInDatabase, security))
					return;				
							
				BulletinHeaderPacket bhp = BulletinStore.loadBulletinHeaderPacket(db, key, security);
				if(! bhp.isAllPrivate())
				{
					infos.add(key.getLocalId());
				}
			}
			catch (Exception e)
			{
				log("Error checking bulletin status");
				String accountInfo = MartusCrypto.formatAccountIdForLog(key.getAccountId());
				log(accountInfo);
				log(key.getLocalId());
				e.printStackTrace();
			}
		}

		Vector infos = new Vector();
	}

	private boolean isSignatureOk(String myAccountId, Vector parameters, String signature, MartusCrypto verifier)
	{
		return verifier.verifySignatureOfVectorOfStrings(parameters, myAccountId, signature);
	}

	private Vector checkSignature(String myAccountId, Vector parameters, String signature)
	{
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			log("ERROR: Signature Failed");
			log("Account: " + MartusCrypto.formatAccountIdForLog(myAccountId));
			log("parameters: " + parameters.toString());
			log("signature: " + signature);
			Vector error = new Vector(); 
			error.add(NetworkInterfaceConstants.SIG_ERROR);			
			return error;
		}
		return null;
	}
	
	void log(String message)
	{
		server.log("Amp handler: " + message);
	}

	ServerForAmplifiers server;
}
