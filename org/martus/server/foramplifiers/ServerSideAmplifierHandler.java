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

package org.martus.server.foramplifiers;

import java.util.Vector;

import org.martus.common.AmplifierNetworkInterface;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MartusSecurity;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.utilities.MartusServerUtilities;
import org.martus.util.ByteArrayInputStreamWithSeek;
import org.martus.util.Base64.InvalidBase64Exception;

public class ServerSideAmplifierHandler implements AmplifierNetworkInterface
{
	public ServerSideAmplifierHandler(ServerForAmplifiers serverToUse)
	{
		server = serverToUse;
	}
	
	/// Begin Interface //
	
	public Vector getAccountIds(String myAccountId, Vector parameters, String signature)
	{
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
				LocallIdOfPublicBulletinsCollector collector = new LocallIdOfPublicBulletinsCollector();
				Database db = server.getDatabase();
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
		
		Vector result = new Vector();
		try
		{
			String publicCode = MartusSecurity.getFormattedPublicCode(myAccountId); 
			if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
			{
				result.add(NetworkInterfaceConstants.SIG_ERROR);
				log("Amp getAccountIds bad sig: " + publicCode);
				return result;
			}
			
			log("Amp getAccountIds: " + publicCode);
			AccountVisitor visitor = new AccountVisitor();
			server.getDatabase().visitAllAccounts(visitor);
			
			result.add(NetworkInterfaceConstants.OK);
			result.add(visitor.getAccounts());
			log("Amp getAccountIds exit OK");
			return result;
		}
		catch (InvalidBase64Exception e)
		{
			log("Amp getAccountIds ERROR");
			e.printStackTrace();
			result.add(NetworkInterfaceConstants.SERVER_ERROR);
			return result;
		}
	}

	public Vector getContactInfo(String myAccountId, Vector parameters, String signature)
	{
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		Vector result = new Vector();
		try
		{
			String publicCode = MartusSecurity.getFormattedPublicCode(myAccountId); 
			if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
			{
				result.add(NetworkInterfaceConstants.SIG_ERROR);
				log("Amp getAccountContactInfo bad sig: " + publicCode);
				return result;
			}
			

			if(parameters.size() != 1)
			{
				result.add(NetworkInterfaceConstants.INCOMPLETE);
				log("Amp getAccountContactInfo incomplete request");
				return result;
			}

			result = server.getContactInfo((String)parameters.get(0));
			return result;
		}
		catch (Exception e)
		{
			log("Amp getAccountContactInfo ERROR");
			e.printStackTrace();
			result.add(NetworkInterfaceConstants.SERVER_ERROR);
			return result;
		}
	}
	
	public Vector getPublicBulletinLocalIds(String myAccountId, Vector parameters, String signature)
	{
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(NetworkInterfaceConstants.SIG_ERROR);
			return result;
		}

		String accountString = (String) parameters.get(0);

		LocallIdOfPublicBulletinsCollector collector = new LocallIdOfPublicBulletinsCollector();
		Database db = server.getDatabase();
		db.visitAllRecordsForAccount(collector, accountString);
		
		result.add(NetworkInterfaceConstants.OK);
		result.add(collector.infos);
		
		return result;
	}
	
	public Vector getAmplifierBulletinChunk(String myAccountId, Vector parameters, String signature)
	{
		if(!server.isAuthorizedAmp(myAccountId))
			return server.returnSingleResponseAndLog(" returning NOT_AUTHORIZED", NetworkInterfaceConstants.NOT_AUTHORIZED);

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(NetworkInterfaceConstants.SIG_ERROR);
			return result;
		}
		
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
				
				DatabaseKey burKey = MartusServerUtilities.getBurKey(key);
				String burInDatabase = server.getDatabase().readRecord(burKey, server.getSecurity());
				if(!MartusServerUtilities.wasBurCreatedByThisCrypto(burInDatabase, server.getSecurity()))
					return;				
							
				String headerXml = server.getDatabase().readRecord(key, server.getSecurity());
				byte[] headerBytes = headerXml.getBytes("UTF-8");
				
				ByteArrayInputStreamWithSeek headerIn = new ByteArrayInputStreamWithSeek(headerBytes);
				BulletinHeaderPacket bhp = new BulletinHeaderPacket("");
				bhp.loadFromXml(headerIn, null);
				if(! bhp.isAllPrivate())
				{
					infos.add(key.getLocalId());
				}
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}

		Vector infos = new Vector();
	}

	private boolean isSignatureOk(String myAccountId, Vector parameters, String signature, MartusCrypto verifier)
	{
		return verifier.verifySignatureOfVectorOfStrings(parameters, myAccountId, signature);
	}
	
	void log(String message)
	{
		server.log(message);
	}
	
	ServerForAmplifiers server;
}
