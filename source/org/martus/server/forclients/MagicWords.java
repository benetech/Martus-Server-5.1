/*

The Martus(tm) free, social justice documentation and
monitoring software. Copyright (C) 2001-2004, Beneficent
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Vector;

import org.martus.server.main.MartusServer;
import org.martus.util.UnicodeReader;

class MagicWords
{
	public MagicWords(MartusServer server)
	{
		coreServer = server;
		magicWordEntries = new Vector();
	}
	
	public void loadMagicWords(File magicWordsFile) throws IOException
	{
		magicWordEntries.removeAllElements();
		try
		{
			UnicodeReader reader = new UnicodeReader(magicWordsFile);
			String line = null;
			while( (line = reader.readLine()) != null)
			{
				if(line.trim().length() == 0)
					coreServer.log("Warning: Found blank line in " + magicWordsFile.getPath());
				else
					add(MagicWords.normalizeMagicWord(line));
			}
			reader.close();
		}
		catch(FileNotFoundException nothingToWorryAbout)
		{
		}
	}
	
	public void add(String magicWordFileEntry)
	{
		if(!contains(getMagicWordFromFileEntry(magicWordFileEntry)))
			magicWordEntries.add(new MagicWordEntry(magicWordFileEntry));
	}
	
	public boolean isValidMagicWord(String tryMagicWord)
	{
		return (contains(normalizeMagicWord(tryMagicWord)));
	}

	private boolean contains(String magicWordToFind)
	{
		for(int i = 0; i<magicWordEntries.size(); ++i)
		{
			MagicWordEntry entry = (MagicWordEntry)magicWordEntries.get(i);
			if(entry.getMagicWord().equals(magicWordToFind))
				return true;
		}
		return false;
	}
	
	public int size()
	{
		return magicWordEntries.size();
	}
	
	static String normalizeMagicWord(String original)
	{
		return original.toLowerCase().trim().replaceAll("\\s", "");
	}

	public String getMagicWordFromFileEntry(String magicWordEntry)
	{
		return magicWordEntry;
	}
	
	class MagicWordEntry
	{
		public MagicWordEntry(String magicWordEntry)
		{
			magicWord = getMagicWordFromFileEntry(magicWordEntry);
			groupName = null;
		}
		
		public String getMagicWord()
		{
			return magicWord;
		}
		
		public String getGroupName()
		{
			return groupName;
		}
		
		String magicWord;
		String groupName;
	}
	
	Vector magicWordEntries; 
	MartusServer coreServer;
}