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

package org.martus.server.tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import org.martus.common.crypto.MartusCrypto;
import org.martus.common.crypto.MartusSecurity;
import org.martus.common.crypto.MartusCrypto.AuthorizationFailedException;
import org.martus.common.utilities.MartusServerUtilities;

public class IsPassphraseValid
{
	public static void main(String[] args)
	{
		File keyPairFile = null;
		boolean prompt = true;
		
		for (int i = 0; i < args.length; i++)
		{
			if( args[i].startsWith("--keypair") )
			{
				keyPairFile = new File(args[i].substring(args[i].indexOf("=")+1));
			}
			
			if( args[i].startsWith("--no-prompt") )
			{
				prompt = false;
			}
		}
		
		if(keyPairFile == null)
		{
				System.err.println("Error: Incorrect argument.\nIsPassphraseValid --keypair=/path/keypair.dat [--no-prompt]" );
				System.err.flush();
				System.exit(2);
		}
		
		if(!keyPairFile.isFile() || !keyPairFile.exists() )
		{
			System.err.println("Error: " + keyPairFile.getAbsolutePath() + " is not a file" );
			System.err.flush();
			System.exit(3);
		}
		
		if(prompt)
		{
			System.out.print("Enter passphrase: ");
			System.out.flush();
		}

		BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
		String passphrase = null;
		try
		{
			passphrase = stdin.readLine();
		}
		catch (IOException e)
		{
			System.err.println("Error: " + e.toString() );
			System.err.flush();
			System.exit(3);
		}

		try
		{
			MartusSecurity security = (MartusSecurity) MartusServerUtilities.loadCurrentMartusSecurity(keyPairFile, passphrase);
			String publicCode = MartusCrypto.computePublicCode(security.getPublicKeyString());
			System.out.println("Public Code: " + MartusCrypto.formatPublicCode(publicCode));
			System.exit(0);
		}
		catch (AuthorizationFailedException e)
		{
			System.err.println("Error: " + e.toString() );
			System.err.flush();
			System.exit(1);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.toString() );
			System.err.flush();
			System.exit(3);
		}
	}
}