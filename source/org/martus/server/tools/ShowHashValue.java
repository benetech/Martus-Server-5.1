package org.martus.server.tools;

import org.martus.common.database.FileDatabase;

public class ShowHashValue 
{
	public static void main(String[] args) 
	{
		if(args.length != 1)
		{
			System.out.println("ShowHashValue <string>");
			System.out.println("   Shows the hash (packet bucket) of a string");
			System.exit(2);
		}
		
		System.out.println(FileDatabase.getBaseBucketName(args[0]));
		System.exit(0);
	}
}
