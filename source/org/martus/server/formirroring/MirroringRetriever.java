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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Vector;

import org.martus.common.LoggerInterface;
import org.martus.common.ProgressMeterInterface;
import org.martus.common.MartusUtilities.ServerErrorException;
import org.martus.common.bulletin.BulletinZipUtilities;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MartusCrypto.MartusSignatureException;
import org.martus.common.database.DatabaseKey;
import org.martus.common.network.NetworkInterfaceConstants;
import org.martus.common.network.NetworkResponse;
import org.martus.common.network.mirroring.CallerSideMirroringGatewayInterface;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.server.main.ServerBulletinStore;
import org.martus.util.Base64.InvalidBase64Exception;

public class MirroringRetriever implements LoggerInterface
{
	public MirroringRetriever(ServerBulletinStore storeToUse, CallerSideMirroringGatewayInterface gatewayToUse, 
						String ipToUse, LoggerInterface loggerToUse)
	{
		store = storeToUse;
		gateway = gatewayToUse;
		ip = ipToUse;
		logger = loggerToUse;
		
		uidsToRetrieve = new Vector();
		accountsToRetrieve = new Vector();
	}
	
	static class MissingBulletinUploadRecordException extends Exception {}
	
	public void retrieveNextBulletin()
	{
		UniversalId uid = getNextUidToRetrieve();
		if(uid == null)
			return;
			
		shouldSleepNextCycle = false;
			
		try
		{
			String publicCode = MartusCrypto.getFormattedPublicCode(uid.getAccountId());
			logNotice("Getting bulletin: " + publicCode + "->" + uid.getLocalId());
			String bur = retrieveBurFromMirror(uid);
			File zip = File.createTempFile("$$$MirroringRetriever", null);
			try
			{
				zip.deleteOnExit();
				retrieveOneBulletin(zip, uid);
				BulletinHeaderPacket bhp = store.saveZipFileToDatabase(zip, uid.getAccountId());
				store.writeBur(bhp, bur);
			}
			finally
			{
				zip.delete();
			}
		}
		catch(ServerErrorException e)
		{
			logError("Supplier server: " + e);
		}
		catch(ServerNotAvailableException e)
		{
			// TODO: Notify once per hour that something is wrong
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
	}
	
	static class ServerNotAvailableException extends Exception {}

	private String retrieveBurFromMirror(UniversalId uid)
		throws MartusSignatureException, MissingBulletinUploadRecordException, ServerNotAvailableException
	{
		NetworkResponse response = gateway.getBulletinUploadRecord(getSecurity(), uid);
		String resultCode = response.getResultCode();
		if(resultCode.equals(NetworkInterfaceConstants.NO_SERVER))
		{
			throw new ServerNotAvailableException();
		}
		if(!resultCode.equals(NetworkInterfaceConstants.OK))
		{
			throw new MissingBulletinUploadRecordException();
		}
		String bur = (String)response.getResultVector().get(0);
		return bur;
	}
	
	UniversalId getNextUidToRetrieve()
	{
		try
		{
			if(uidsToRetrieve.size() > 0)
			{
				return (UniversalId)uidsToRetrieve.remove(0);
			}

			String nextAccountId = getNextAccountToRetrieve();
			if(nextAccountId == null)
				return null;

			String publicCode = MartusCrypto.getFormattedPublicCode(nextAccountId);
			//log("listBulletins: " + publicCode);
			NetworkResponse response = gateway.listBulletinsForMirroring(getSecurity(), nextAccountId);
			if(response.getResultCode().equals(NetworkInterfaceConstants.OK))
			{
				Vector infos = response.getResultVector();
				uidsToRetrieve = listOnlyPacketsThatWeWant(nextAccountId, infos);
				if(infos.size()>0 || uidsToRetrieve.size()>0)
					logInfo("listBulletins: " + publicCode + 
						" -> " + infos.size() + " -> " + uidsToRetrieve.size());
			}
		}
		catch (Exception e)
		{
			logError("MirroringRetriever.getNextUidToRetrieve: " + e);
			e.printStackTrace();
		}

		return null;
	}

	Vector listOnlyPacketsThatWeWant(String accountId, Vector infos)
	{
		Vector uids = new Vector();
		for(int i=0; i < infos.size(); ++i)
		{
			Vector info = (Vector)infos.get(i);
			String localId = (String)info.get(0);
			UniversalId uid = UniversalId.createFromAccountAndLocalId(accountId, localId);
			DatabaseKey key = DatabaseKey.createSealedKey(uid);
			if(!store.doesBulletinRevisionExist(key) && !store.isHidden(key))
				uids.add(uid);
		}
		return uids;
	}

	String getNextAccountToRetrieve()
	{
		if(accountsToRetrieve.size() > 0)
			return (String)accountsToRetrieve.remove(0);

		if(isSleeping())
			return null;

		if(shouldSleepNextCycle)
		{
			//log("Sleeping for " + ServerForMirroring.inactiveSleepMillis / 1000 / 60 + " minutes");
			sleepUntil = System.currentTimeMillis() + ServerForMirroring.inactiveSleepMillis;
			shouldSleepNextCycle = false;
			return null;
		}

		shouldSleepNextCycle = true;

		try
		{
			logInfo("Getting list of accounts");
			NetworkResponse response = gateway.listAccountsForMirroring(getSecurity());
			String resultCode = response.getResultCode();
			if(resultCode.equals(NetworkInterfaceConstants.OK))
			{
				accountsToRetrieve.addAll(response.getResultVector());
				logNotice("Account count:" + accountsToRetrieve.size());
			}
			else if(!resultCode.equals(NetworkInterfaceConstants.NO_SERVER))
			{
				logError("error returned by " + ip + ": " + resultCode);
			}
		}
		catch (Exception e)
		{
			logError("getNextAccountToRetrieve: " + e);
			e.printStackTrace();
		}
		return null;
	}

	private boolean isSleeping()
	{
		return System.currentTimeMillis() < sleepUntil;
	}
	
	void retrieveOneBulletin(File destFile, UniversalId uid) throws InvalidBase64Exception, IOException, MartusSignatureException, ServerErrorException
	{
		FileOutputStream out = new FileOutputStream(destFile);

		int chunkSize = MIRRORING_MAX_CHUNK_SIZE;
		ProgressMeterInterface nullProgressMeter = null;
		int totalLength = BulletinZipUtilities.retrieveBulletinZipToStream(uid, out, chunkSize, gateway, getSecurity(), nullProgressMeter);

		out.close();

		if(destFile.length() != totalLength)
		{
			logError("file=" + destFile.length() + ", returned=" + totalLength);
			throw new ServerErrorException("totalSize didn't match data length");
		}
	}
	
	private MartusCrypto getSecurity()
	{
		return store.getSignatureGenerator();
	}

	private String createLogString(String message)
	{
		return "Mirror calling " + ip + ": " + message;
	}

	public void logError(String message)
	{
		logger.logError(createLogString(message));
	}
	
	public void logInfo(String message)
	{
		logger.logInfo(createLogString(message));
	}

	public void logNotice(String message)
	{
		logger.logNotice(createLogString(message));
	}
	
	public void logDebug(String message)
	{
		logger.logDebug(createLogString(message));
	}
	
	ServerBulletinStore store;	
	CallerSideMirroringGatewayInterface gateway;
	String ip;
	LoggerInterface logger;
	
	Vector uidsToRetrieve;
	Vector accountsToRetrieve;

	public boolean shouldSleepNextCycle;
	public long sleepUntil;
	
	static final int MIRRORING_MAX_CHUNK_SIZE = 1024 * 1024;

}
