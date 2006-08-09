/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2002-2006, Beneficent
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

import java.io.UnsupportedEncodingException;
import java.util.Vector;

import org.martus.common.LoggerInterface;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.network.NetworkInterface;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.util.Base64;
import org.martus.util.LoggerUtil;


public class ServerSideNetworkHandler implements NetworkInterface, NetworkInterfaceConstants, LoggerInterface
{

	public ServerSideNetworkHandler(ServerForClientsInterface serverToUse)
	{
		server = serverToUse;
	}
	
	private String createLogString(String message)
	{
		return "Client SSL handler: " + message;
	}

	public void logError(String message)
	{
		server.logError(createLogString(message));
	}
	
	public void logError(Exception e)
	{
		logError(LoggerUtil.getStackTrace(e));
	}

	public void logError(String message, Exception e)
	{
		logError(message);
		logError(e);
	}

	public void logInfo(String message)
	{
		server.logInfo(createLogString(message));
	}

	public void logNotice(String message)
	{
		server.logNotice(createLogString(message));
	}
	
	public void logWarning(String message)
	{
		server.logWarning(createLogString(message));
	}

	public void logDebug(String message)
	{
		server.logDebug(createLogString(message));
	}

	// begin ServerInterface	
	public Vector getServerInfo(Vector reservedForFuture)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getServerInfo");
			
			if(server.shouldSimulateBadConnection())
			{
				logWarning("Simulating bad connection!");
				int ONE_MINUTE_OF_MILLIS = 60*1000;
				try
				{
					Thread.sleep(ONE_MINUTE_OF_MILLIS);
				}
				catch (InterruptedException e)
				{
					logError(e);
				}
			}
			
			String version = server.ping();
			Vector data = new Vector();
			data.add(version);
			
			Vector result = new Vector();
			result.add(OK);
			result.add(data);
			logDebug("getServerInfo: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getUploadRights(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getUploadRights");

			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			
			int index = 0;
			String tryMagicWord = (String)parameters.get(index++);
			logNotice("requested " + server.getPublicCode(myAccountId));
			
			String legacyResult = server.requestUploadRights(myAccountId, tryMagicWord);
			result.add(legacyResult);
			logDebug("getUploadRights: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getSealedBulletinIds(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getSealedBulletinIds");

			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			
			int index = 0;
			String authorAccountId = (String)parameters.get(index++);
			Vector retrieveTags = new Vector();
			if(index < parameters.size())
				retrieveTags = (Vector)parameters.get(index++);
			
			if(myAccountId.equals(authorAccountId))
				result = server.listMySealedBulletinIds(authorAccountId, retrieveTags);
			else
				result = server.listFieldOfficeSealedBulletinIds(myAccountId, authorAccountId, retrieveTags);
			logDebug("getSealedBulletinIds: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getDraftBulletinIds(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getDraftBulletinIds");

			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			
			int index = 0;
			String authorAccountId = (String)parameters.get(index++);
			Vector retrieveTags = new Vector();
			if(index < parameters.size())
				retrieveTags = (Vector)parameters.get(index++);

			if(myAccountId.equals(authorAccountId))
				result = server.listMyDraftBulletinIds(authorAccountId, retrieveTags);
			else
				result = server.listFieldOfficeDraftBulletinIds(myAccountId, authorAccountId, retrieveTags);
			logDebug("getDraftBulletinIds: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getFieldOfficeAccountIds(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getFieldOfficeAccountIds");
			
			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			
			int index = 0;
			String hqAccountId = (String)parameters.get(index++);
			logNotice("getFieldOfficeAccountIds requested for " + server.getPublicCode(hqAccountId));

			Vector legacyResult = server.listFieldOfficeAccounts(hqAccountId);
			String resultCode = (String)legacyResult.get(0);
			legacyResult.remove(0);
			
			result.add(resultCode);
			result.add(legacyResult);
			logDebug("getFieldOfficeAccountIds: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector putBulletinChunk(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("putBulletinChunk");

			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			
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
			logDebug("putBulletinChunk: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getBulletinChunk(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getBulletinChunk");
				
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
			logDebug("getBulletinChunk: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getPacket(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getPacket");

			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			
			int index = 0;
			String authorAccountId = (String)parameters.get(index++);
			String bulletinLocalId= (String)parameters.get(index++);
			String packetLocalId= (String)parameters.get(index++);
			boolean base64EncodeData = false;
			if(parameters.size() > 3 && parameters.get(index++).equals(NetworkInterfaceConstants.BASE_64_ENCODED))
				base64EncodeData = true;
			
			logNotice("getPacketId " + packetLocalId + " for bulletinId " + bulletinLocalId);

			Vector legacyResult = server.getPacket(myAccountId, authorAccountId, bulletinLocalId, packetLocalId);
			String resultCode = (String)legacyResult.remove(0);
			if(legacyResult.size() == 1)
			{	
				String packet = (String)legacyResult.get(0);
				if(base64EncodeData)
					packet = Base64.encode(packet);
			
				Vector newResult = new Vector();
				newResult.add(packet);
				legacyResult = newResult;
			}
			
			result.add(resultCode);
			result.add(legacyResult);
			logDebug("getPacket: Exit");
			return result;
		}
		catch (UnsupportedEncodingException e)
		{
			logError("UnsupportedEncodingException:", e);
			Vector errorResult = new Vector();
			errorResult.add(INVALID_DATA);
			return errorResult;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector deleteDraftBulletins(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("deleteDraftBulletins");

			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();

			result.add(server.deleteDraftBulletins(myAccountId, parameters, signature));
			logDebug("deleteDraftBulletins: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}
	
	// TODO: The following is for diagnostics only! 
	// as soon as we resolve the contact info signature problem,
	// this member variable should be removed 
	static Vector badContactInfoAccounts = new Vector();
	
	public Vector putContactInfo(String myAccountId, Vector parameters, String signature) 
	{
		server.clientConnectionStart();
		try
		{
			logInfo("putContactInfo");
			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			result.add(server.putContactInfo(myAccountId, parameters));
			logDebug("putContactInfo: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getNews(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getNews");
			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
				
			String versionLabel = "";
			String versionBuildDate = "";
			
			if(parameters.size() >= 2)
			{
				int index = 0;
				versionLabel = (String)parameters.get(index++);
				versionBuildDate = (String)parameters.get(index++);
			}

			result = server.getNews(myAccountId, versionLabel, versionBuildDate);
			logDebug("getNews: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	public Vector getServerCompliance(String myAccountId, Vector parameters, String signature)
	{
		server.clientConnectionStart();
		try
		{
			logInfo("getServerCompliance");
			Vector result = checkSignature(myAccountId, parameters, signature);
			if(result != null)
				return result;
			result = new Vector();
			result = server.getServerCompliance();
			logDebug("getServerCompliance: Exit");
			return result;
		}
		finally
		{
			server.clientConnectionExit();
		}
	}

	private Vector checkSignature(String myAccountId, Vector parameters, String signature)
	{
		if(!isSignatureOk(myAccountId, parameters, signature, server.getSecurity()))
		{
			logError("Signature Failed");
			logError("Account: " + MartusCrypto.formatAccountIdForLog(myAccountId));
			logError("parameters: " + parameters.toString());
			logError("signature: " + signature);
			Vector error = new Vector(); 
			error.add(SIG_ERROR);			
			return error;
		}
		return null;
	}
	
	private boolean isSignatureOk(String myAccountId, Vector parameters, String signature, MartusCrypto verifier)
	{
		//server.log("request for client " + server.getPublicCode(myAccountId));
		return verifier.verifySignatureOfVectorOfStrings(parameters, myAccountId, signature);
	}

	final static String defaultReservedResponse = "";

	ServerForClientsInterface server;
}
