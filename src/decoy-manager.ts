/**
 * Decoy Manager - Plausible Deniability System
 * Manages dual password authentication and decoy file generation
 */

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import fs from 'fs';
import path from 'path';
import { FileRecord, FileStatus } from './types';

export interface DecoyFile {
  id: string;
  name: string;
  content: Buffer;
  mimeType: string;
  size: number;
}

/**
 * Generate realistic fake files for decoy account
 */
export const generateDecoyFiles = (): DecoyFile[] => {
  const files: DecoyFile[] = [];
  
  // Generate 5-10 fake files
  const fileCount = 5 + Math.floor(Math.random() * 6);
  
  for (let i = 0; i < fileCount; i++) {
    const fileType = Math.random();
    
    if (fileType < 0.4) {
      // Text document (40% chance)
      files.push(generateFakeTextDocument());
    } else if (fileType < 0.7) {
      // Image (30% chance)
      files.push(generateFakeImage());
    } else {
      // Plain text file (30% chance)
      files.push(generateFakePlainText());
    }
  }
  
  return files;
};

/**
 * Generate fake text document with Lorem Ipsum
 */
const generateFakeTextDocument = (): DecoyFile => {
  const titles = [
    'Meeting Notes',
    'Project Plan',
    'Budget Report',
    'Weekly Summary',
    'Task List',
    'Ideas and Notes',
    'Research Notes',
    'Draft Document'
  ];
  
  const loremIpsum = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.

Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.

Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt.`;
  
  const title = titles[Math.floor(Math.random() * titles.length)];
  const content = Buffer.from(loremIpsum);
  
  return {
    id: uuid(),
    name: `${title}.txt`,
    content,
    mimeType: 'text/plain',
    size: content.length
  };
};

/**
 * Generate fake image (1x1 pixel PNG with random color)
 */
const generateFakeImage = (): DecoyFile => {
  const names = [
    'photo',
    'image',
    'picture',
    'screenshot',
    'document_scan',
    'receipt',
    'diagram',
    'chart'
  ];
  
  const name = names[Math.floor(Math.random() * names.length)];
  const timestamp = Date.now() - Math.floor(Math.random() * 90 * 24 * 60 * 60 * 1000);
  
  // Generate a simple 1x1 PNG (smallest valid PNG)
  const pngHeader = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1 dimensions
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
    0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
    0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
    0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
    0x44, 0xAE, 0x42, 0x60, 0x82
  ]);
  
  return {
    id: uuid(),
    name: `${name}_${timestamp}.png`,
    content: pngHeader,
    mimeType: 'image/png',
    size: pngHeader.length
  };
};

/**
 * Generate fake plain text file
 */
const generateFakePlainText = (): DecoyFile => {
  const names = [
    'notes',
    'todo',
    'ideas',
    'reminders',
    'shopping_list',
    'contacts',
    'passwords',
    'bookmarks'
  ];
  
  const contents = [
    'Buy groceries\nPay bills\nCall dentist\nFinish report',
    'Meeting at 2pm\nLunch with Sarah\nGym at 6pm',
    'Project deadline: Friday\nReview code\nUpdate documentation',
    'Remember to:\n- Send email\n- Update calendar\n- Backup files',
    'Ideas:\n- New feature concept\n- Improve UI\n- Add tests'
  ];
  
  const name = names[Math.floor(Math.random() * names.length)];
  const contentText = contents[Math.floor(Math.random() * contents.length)];
  const content = Buffer.from(contentText);
  
  return {
    id: uuid(),
    name: `${name}.txt`,
    content,
    mimeType: 'text/plain',
    size: content.length
  };
};

/**
 * Hash decoy password
 */
export const hashDecoyPassword = async (password: string): Promise<string> => {
  return await bcrypt.hash(password, 12);
};

/**
 * Verify if password matches decoy password
 */
export const verifyDecoyPassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};

/**
 * Validate decoy password (must be different from real password)
 */
export const validateDecoyPassword = async (
  decoyPassword: string,
  realPasswordHash: string
): Promise<{ valid: boolean; error?: string }> => {
  // Check if decoy password is same as real password
  const isSame = await bcrypt.compare(decoyPassword, realPasswordHash);
  if (isSame) {
    return { valid: false, error: 'Decoy password must be different from your real password' };
  }
  
  // Check password strength
  if (decoyPassword.length < 8) {
    return { valid: false, error: 'Decoy password must be at least 8 characters' };
  }
  
  return { valid: true };
};
