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
import java.io.IOException;
import java.net.InetAddress;
import java.util.Vector;

import org.martus.amplifier.ServerCallbackInterface;
import org.martus.common.LoggerInterface;
import org.martus.common.MartusUtilities;
import org.martus.common.MartusUtilities.InvalidPublicKeyFileException;
import org.martus.common.MartusUtilities.PublicInformationInvalidException;
import org.martus.common.crypto.MartusCrypto;
import org.martus.common.database.Database;
import org.martus.common.database.DatabaseKey;
import org.martus.common.database.ReadableDatabase;
import org.martus.common.network.MartusXmlRpcServer;
import org.martus.common.network.mirroring.CallerSideMirroringGateway;
import org.martus.common.network.mirroring.CallerSideMirroringGatewayForXmlRpc;
import org.martus.common.network.mirroring.MirroringInterface;
import org.martus.common.network.mirroring.CallerSideMirroringGatewayForXmlRpc.SSLSocketSetupException;
import org.martus.common.packet.BulletinHeaderPacket;
import org.martus.common.packet.UniversalId;
import org.martus.server.main.BulletinUploadRecord;
import org.martus.server.main.MartusServer;
import org.martus.server.main.ServerBulletinStore;
import org.martus.util.Base64;
import org.martus.util.DirectoryUtils;
import org.martus.util.LoggerUtil;
import org.martus.util.inputstreamwithseek.InputStreamWithSeek;


public class ServerForMirroring implements ServerSupplierInterface
{
	public ServerForMirroring(MartusServer coreServerToUse, LoggerInterface loggerToUse) throws IOException, InvalidPublicKeyFileException, PublicInformationInvalidException  
	{
		coreServer = coreServerToUse;
		logger = loggerToUse;
	}
	
	public ServerBulletinStore getStore()
	{
		return coreServer.getStore();
	}

	public Vector getDeleteOnStartupFiles()
	{
		Vector startupFiles = new Vector();
		startupFiles.add(getMirrorConfigFile());
		return startupFiles;
	}

	public Vector getDeleteOnStartupFolders()
	{
		Vector startupFolders = new Vector();
		startupFolders.add(getMirrorsWeWillCallDirectory());
		startupFolders.add(getAuthorizedCallersDirectory());
		return startupFolders;
	}
	
	public void deleteStartupFiles()
	{
		DirectoryUtils.deleteEntireDirectoryTree(getDeleteOnStartupFolders());
		MartusUtilities.deleteAllFiles(getDeleteOnStartupFiles());
	}
	
	private String createLogString(String message)
	{
		return "ServerForMirror " + message;
	}

	public void logError(String message)
	{
		logger.logError(createLogString(message));
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
		logger.logInfo(createLogString(message));
	}

	public void logNotice(String message)
	{
		logger.logNotice(createLogString(message));
	}
	
	public void logWarning(String message)
	{
		logger.logWarning(createLogString(message));
	}

	public void logDebug(String message)
	{
		logger.logDebug(createLogString(message));
	}
	
	
	public File getMirrorConfigFile()
	{
		return new File(coreServer.getStartupConfigDirectory(), MIRRORCONFIGFILENAME);
	}
	
	public void verifyConfigurationFiles()
	{
		// nothing to do yet
	}
	
	public void loadConfigurationFiles() throws IOException, InvalidPublicKeyFileException, PublicInformationInvalidException
	{
		if(getMirrorConfigFile().exists())
		{
			long oneSecondOfMillis = 1000;
			long oneMinuteOfMillis = 60 * oneSecondOfMillis;

			mirroringIntervalMillis = oneSecondOfMillis;
			inactiveSleepMillis = oneMinuteOfMillis;
		}
		logNotice("MirroringInterval (seconds): " + mirroringIntervalMillis/1000);
		logNotice("InactiveSleep (minutes): " + inactiveSleepMillis/1000/60);

		File authorizedCallersDir = getAuthorizedCallersDirectory();
		authorizedCallers = coreServer.loadServerPublicKeys(authorizedCallersDir, "Mirror");
		logNotice("Authorized " + authorizedCallers.size() + " Mirrors to call us");
	}
	
	public void addListeners() throws IOException, InvalidPublicKeyFileException, PublicInformationInvalidException
	{
		logInfo("Initializing ServerForMirroring");
		
		InetAddress mainIpAddress = MartusServer.getMainIpAddress();
		int port = MirroringInterface.MARTUS_PORT_FOR_MIRRORING;
		if(coreServer.wantsDevelopmentMode())
			port += 
				ServerCallbackInterface.DEVELOPMENT_MODE_PORT_DELTA;
		logNotice("Opening port " + mainIpAddress +":" + port + " for mirroring...");
		SupplierSideMirroringHandler supplierHandler = new SupplierSideMirroringHandler(this, getSecurity());
		MartusXmlRpcServer.createSSLXmlRpcServer(supplierHandler, MirroringInterface.DEST_OBJECT_NAME, port, mainIpAddress);

		logNotice("Mirroring port opened");
	}

	// Begin ServerSupplierInterface
	public Vector getPublicInfo()
	{
		try
		{
			Vector result = new Vector();
			result.add(getSecurity().getPublicKeyString());
			result.add(getSecurity().getSignatureOfPublicKey());
			return result;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return new Vector();
		}
	}
	
	public boolean isAuthorizedForMirroring(String callerAccountId)
	{
		return authorizedCallers.contains(callerAccountId);
	}

	public Vector listAccountsForMirroring()
	{
		class Collector implements Database.AccountVisitor
		{
			public void visit(String accountId)
			{
				accounts.add(accountId);
			}
			
			Vector accounts = new Vector();
		}

		Collector collector = new Collector();		
		getDatabase().visitAllAccounts(collector);
		return collector.accounts;
	}

	public Vector listBulletinsForMirroring(String authorAccountId)
	{
		class Collector implements Database.PacketVisitor
		{
			public void visit(DatabaseKey key)
			{
				try
				{
					if(key.isDraft())
						return;
					if(!BulletinHeaderPacket.isValidLocalId(key.getLocalId()))
						return;
					InputStreamWithSeek in = getDatabase().openInputStream(key, null);
					byte[] sigBytes = BulletinHeaderPacket.verifyPacketSignature(in, getSecurity());
					in.close();
					String sigString = Base64.encode(sigBytes);
					Vector info = new Vector();
					info.add(key.getLocalId());
					info.add(sigString);
					infos.add(info);
				}
				catch (Exception e)
				{
					logError("listBulletins " + e);
				}
			}
			
			Vector infos = new Vector();
		}

		Collector collector = new Collector();		
		getDatabase().visitAllRecordsForAccount(collector, authorAccountId);
		return collector.infos;
	}
	
	public String getBulletinUploadRecord(String authorAccountId, String bulletinLocalId)
	{
		UniversalId uid = UniversalId.createFromAccountAndLocalId(authorAccountId, bulletinLocalId);
		DatabaseKey headerKey = DatabaseKey.createSealedKey(uid);
		DatabaseKey burKey = BulletinUploadRecord.getBurKey(headerKey);
		try
		{
			String bur = getDatabase().readRecord(burKey, getSecurity());
			return bur;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}
	
	public Vector getBulletinChunkWithoutVerifyingCaller(String authorAccountId, String bulletinLocalId, int chunkOffset, int maxChunkSize)
	{
		return coreServer.getBulletinChunkWithoutVerifyingCaller(authorAccountId, bulletinLocalId, chunkOffset, maxChunkSize);
	}
	//End ServerSupplierInterface

	MartusCrypto getSecurity()
	{
		return coreServer.getSecurity();
	}

	ReadableDatabase getDatabase()
	{
		return coreServer.getDatabase();
	}
	
	boolean isSecureMode()
	{
		return coreServer.isSecureMode();
	}

	File getAuthorizedCallersDirectory()
	{
		return new File(coreServer.getStartupConfigDirectory(), "mirrorsWhoCallUs");
	}
	
	File getMirrorsWeWillCallDirectory()
	{
		return new File(coreServer.getStartupConfigDirectory(), "mirrorsWhoWeCall");		
	}
	
	public void createGatewaysWeWillCall() throws 
			IOException, InvalidPublicKeyFileException, PublicInformationInvalidException, SSLSocketSetupException
	{
		retrieversWeWillCall = new Vector();

		File toCallDir = getMirrorsWeWillCallDirectory();
		File[] toCallFiles = toCallDir.listFiles();
		if(toCallFiles == null)
			return;
		for (int i = 0; i < toCallFiles.length; i++)
		{
			File toCallFile = toCallFiles[i];
			retrieversWeWillCall.add(createRetrieverToCall(toCallFile));
			if(isSecureMode())
			{
				toCallFile.delete();
				if(toCallFile.exists())
					throw new IOException("delete failed: " + toCallFile);
			}
			logNotice("We will call: " + toCallFile.getName());
		}
		logNotice("Configured to call " + retrieversWeWillCall.size() + " Mirrors");
	}
	
	MirroringRetriever createRetrieverToCall(File publicKeyFile) throws
			IOException, 
			InvalidPublicKeyFileException, 
			PublicInformationInvalidException, 
			SSLSocketSetupException
	{
		String ip = MartusUtilities.extractIpFromFileName(publicKeyFile.getName());
		CallerSideMirroringGateway gateway = createGatewayToCall(ip, publicKeyFile);
		MirroringRetriever retriever = new MirroringRetriever(getStore(), gateway, ip, logger);
		return retriever;
	}
	
	CallerSideMirroringGateway createGatewayToCall(String ip, File publicKeyFile) throws 
			IOException, 
			InvalidPublicKeyFileException, 
			PublicInformationInvalidException, 
			SSLSocketSetupException
	{
		int port = MirroringInterface.MARTUS_PORT_FOR_MIRRORING;
		Vector publicInfo = MartusUtilities.importServerPublicKeyFromFile(publicKeyFile, getSecurity());
		String publicKey = (String)publicInfo.get(0);

		CallerSideMirroringGatewayForXmlRpc xmlRpcGateway = new CallerSideMirroringGatewayForXmlRpc(ip, port); 
		xmlRpcGateway.setExpectedPublicKey(publicKey);
		return new CallerSideMirroringGateway(xmlRpcGateway);
	}

	
	public void doBackgroundTick()
	{
		for(int i = 0; i < retrieversWeWillCall.size(); ++i)
		{	
			((MirroringRetriever)retrieversWeWillCall.get(i)).retrieveNextBulletin();
		}
	}
	
	MartusServer coreServer;
	LoggerInterface logger;
	Vector authorizedCallers;
	MirroringRetriever retriever;
	Vector retrieversWeWillCall;

	static final String MIRRORCONFIGFILENAME = "mirrorConfig.txt";	
	public static long mirroringIntervalMillis = 10 * 1000;	// TODO: Probably 60 seconds
	static long inactiveSleepMillis = 15 * 60 * 1000;
}
