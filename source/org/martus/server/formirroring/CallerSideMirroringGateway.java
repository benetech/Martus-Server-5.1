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

package org.martus.server.formirroring;

import java.util.Vector;

import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MartusCrypto.MartusSignatureException;
import org.martus.common.network.NetworkResponse;
import org.martus.common.packet.UniversalId;

public class CallerSideMirroringGateway implements CallerSideMirroringGatewayInterface
{
	public CallerSideMirroringGateway(MirroringInterface handlerToUse)
	{
		handler = handlerToUse;
	}
	
	public NetworkResponse ping() throws MartusSignatureException
	{
		Vector parameters = new Vector();
		parameters.add(MirroringInterface.CMD_MIRRORING_PING);
		return new NetworkResponse(handler.request("anonymous", parameters, "unsigned"));
	}

	public NetworkResponse listAccountsForMirroring(MartusCrypto signer) throws MartusSignatureException
	{
		Vector parameters = new Vector();
		parameters.add(MirroringInterface.CMD_MIRRORING_LIST_ACCOUNTS);
		String signature = signer.createSignatureOfVectorOfStrings(parameters);
		return new NetworkResponse(handler.request(signer.getPublicKeyString(), parameters, signature));
	}
	
	public NetworkResponse listBulletinsForMirroring(MartusCrypto signer, String authorAccountId) throws MartusSignatureException
	{
		Vector parameters = new Vector();
		parameters.add(MirroringInterface.CMD_MIRRORING_LIST_SEALED_BULLETINS);
		parameters.add(authorAccountId);
		String signature = signer.createSignatureOfVectorOfStrings(parameters);
		return new NetworkResponse(handler.request(signer.getPublicKeyString(), parameters, signature));
	}
	
	public NetworkResponse getBulletinUploadRecord(MartusCrypto signer, UniversalId uid) throws MartusSignatureException
	{
		Vector parameters = new Vector();
		parameters.add(MirroringInterface.CMD_MIRRORING_GET_BULLETIN_UPLOAD_RECORD);
		parameters.add(uid.getAccountId());
		parameters.add(uid.getLocalId());
		String signature = signer.createSignatureOfVectorOfStrings(parameters);
		return new NetworkResponse(handler.request(signer.getPublicKeyString(), parameters, signature));
	}

	public NetworkResponse getBulletinChunk(MartusCrypto signer, String authorAccountId, String bulletinLocalId, 
					int chunkOffset, int maxChunkSize) throws 
			MartusCrypto.MartusSignatureException
	{
		Vector parameters = new Vector();
		parameters.add(MirroringInterface.CMD_MIRRORING_GET_BULLETIN_CHUNK);
		parameters.add(authorAccountId);
		parameters.add(bulletinLocalId);
		parameters.add(new Integer(chunkOffset));
		parameters.add(new Integer(maxChunkSize));
		String signature = signer.createSignatureOfVectorOfStrings(parameters);
		return new NetworkResponse(handler.request(signer.getPublicKeyString(), parameters, signature));
	}
					
	MirroringInterface handler;
}

