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

package org.martus.server.forclients;

import java.util.Vector;

import org.martus.common.crypto.MartusCrypto;
import org.martus.common.network.NetworkInterface;
import org.martus.common.network.NetworkInterfaceConstants;


public class ServerSideNetworkHandler implements NetworkInterface, NetworkInterfaceConstants
{

	public ServerSideNetworkHandler(ServerForClientsInterface serverToUse)
	{
		server = serverToUse;
	}
	
	void log(String message)
	{
		server.log(message);
	}

	// begin ServerInterface	
	public Vector getServerInfo(Vector reservedForFuture)
	{
		server.clientConnectionStart();
		log("getServerInfo");
		
		String version = server.ping();
		Vector data = new Vector();
		data.add(version);
		
		Vector result = new Vector();
		result.add(OK);
		result.add(data);
		
		log("getServerInfo: exit");
			
		server.clientConnectionExit();
		return result;
	}

	public Vector getUploadRights(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("getUploadRights");

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			server.clientConnectionExit();
			result.add(SIG_ERROR);
			return result;
		}

		int index = 0;
		String tryMagicWord = (String)parameters.get(index++);
		server.log("request for client " + server.getPublicCode(myAccountId));
		
		String legacyResult = server.requestUploadRights(myAccountId, tryMagicWord);
		result.add(legacyResult);
		
		server.clientConnectionExit();
		return result;
	}

	public Vector getSealedBulletinIds(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("getSealedBulletinIds");

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);
			server.clientConnectionExit();
			return result;
		}
			
		int index = 0;
		String authorAccountId = (String)parameters.get(index++);
		Vector retrieveTags = new Vector();
		if(index < parameters.size())
			retrieveTags = (Vector)parameters.get(index++);
		
		if(myAccountId.equals(authorAccountId))
			result = server.listMySealedBulletinIds(authorAccountId, retrieveTags);
		else
			result = server.listFieldOfficeSealedBulletinIds(myAccountId, authorAccountId, retrieveTags);

		server.clientConnectionExit();
		return result;
	}

	public Vector getDraftBulletinIds(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("getDraftBulletinIds");

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);			
			server.clientConnectionExit();			
			return result;
		}
			
		int index = 0;
		String authorAccountId = (String)parameters.get(index++);
		Vector retrieveTags = new Vector();
		if(index < parameters.size())
			retrieveTags = (Vector)parameters.get(index++);

		if(myAccountId.equals(authorAccountId))
			result = server.listMyDraftBulletinIds(authorAccountId, retrieveTags);
		else
			result = server.listFieldOfficeDraftBulletinIds(myAccountId, authorAccountId, retrieveTags);

		server.clientConnectionExit();
		return result;
	}

	public Vector getFieldOfficeAccountIds(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("getFieldOfficeAccountIds");
		
		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);			
			server.clientConnectionExit();			
			return result;
		}
			
		int index = 0;
		String hqAccountId = (String)parameters.get(index++);
		server.log("request for client " + server.getPublicCode(hqAccountId));

		Vector legacyResult = server.listFieldOfficeAccounts(hqAccountId);
		String resultCode = (String)legacyResult.get(0);
		legacyResult.remove(0);
		
		result.add(resultCode);
		result.add(legacyResult);
		
		server.clientConnectionExit();
		
		return result;
	}

	public Vector putBulletinChunk(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("putBulletinChunk");

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);			
			server.clientConnectionExit();			
			return result;
		}
			
		int index = 0;
		String authorAccountId = (String)parameters.get(index++);
		String bulletinLocalId= (String)parameters.get(index++);
		int totalSize = ((Integer)parameters.get(index++)).intValue();
		int chunkOffset = ((Integer)parameters.get(index++)).intValue();
		int chunkSize = ((Integer)parameters.get(index++)).intValue();
		String data = (String)parameters.get(index++);

		String legacyResult = server.putBulletinChunk(myAccountId, authorAccountId, bulletinLocalId, 
					totalSize, chunkOffset, chunkSize, data);
		result.add(legacyResult);
		
		server.clientConnectionExit();
		
		return result;
	}

	public Vector getBulletinChunk(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("getBulletinChunk");
			
		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);			
			server.clientConnectionExit();			
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
		
		server.clientConnectionExit();
		
		return result;
	}

	public Vector getPacket(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("getPacket");

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);			
			server.clientConnectionExit();			
			return result;
		}
			
	
		int index = 0;
		String authorAccountId = (String)parameters.get(index++);
		String bulletinLocalId= (String)parameters.get(index++);
		String packetLocalId= (String)parameters.get(index++);

		log("getPacketId " + packetLocalId + " for bulletinId " + bulletinLocalId);

		Vector legacyResult = server.getPacket(myAccountId, authorAccountId, bulletinLocalId, packetLocalId);
		String resultCode = (String)legacyResult.get(0);
		legacyResult.remove(0);
				
		result.add(resultCode);
		result.add(legacyResult);
		
		server.clientConnectionExit();
		
		return result;
	}

	public Vector deleteDraftBulletins(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		log("deleteDraftBulletins");

		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			result.add(SIG_ERROR);			
			server.clientConnectionExit();			
			return result;
		}

		int idCount = ((Integer)parameters.get(0)).intValue();
		String[] idList = new String[idCount];
		for (int i = 0; i < idList.length; i++)
		{
			idList[i] = (String)parameters.get(1+i);
		}

		result.add(server.deleteDraftBulletins(myAccountId, idList));
		
		server.clientConnectionExit();
		return result;
	}
	
	public Vector putContactInfo(String myAccountId, Vector parameters, String signature) 
	{
		server.clientConnectionStart();
		Vector result = new Vector();
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			log("putContactInfo:Signature Error");
			result.add(SIG_ERROR);
			server.clientConnectionExit();
			return result;
		}
		result.add(server.putContactInfo(myAccountId, parameters));
		server.clientConnectionExit();
		return result;
	}

	public Vector getNews(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		Vector result = new Vector();

		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			log("getNews:Signature Error");
			result.add(SIG_ERROR);
			server.clientConnectionExit();
			return result;
		}
		
		String versionLabel = "";
		String versionBuildDate = "";
		
		if(parameters.size() >= 2)
		{
			int index = 0;
			versionLabel = (String)parameters.get(index++);
			versionBuildDate = (String)parameters.get(index++);
		}

		result = server.getNews(myAccountId, versionLabel, versionBuildDate);
		server.clientConnectionExit();
		return result;
	}

	public Vector getServerCompliance(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		Vector result = new Vector();

		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			log("getServerCompliance:Signature Error");
			result.add(SIG_ERROR);
			server.clientConnectionExit();
			return result;
		}
		
		result = server.getServerCompliance();
		server.clientConnectionExit();
		return result;
	}

	private boolean isSignatureOk(String myAccountId, Vector parameters, String signature, MartusCrypto verifier)
	{
		server.log("request for client " + server.getPublicCode(myAccountId));
		return verifier.verifySignatureOfVectorOfStrings(parameters, myAccountId, signature);
	}

	final static String defaultReservedResponse = "";

	ServerForClientsInterface server;
}
