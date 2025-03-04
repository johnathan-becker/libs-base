// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: 73161fea0d182352afe814098c5dc7f78992c523 
// Date: 2016-03-08 22:04:34 +0000 
// ========== End of Keysight Technologies Notice ========== 
/** Declaration of extension methods for base additions

   Copyright (C) 2015 Free Software Foundation, Inc.

   Written by:  Niels Grewe <niels.grewe@halbordnung.de>

   This file is part of the GNUstep Base Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02111 USA.

*/

#ifndef	INCLUDED_NSHashTable_GNUstepBase_h
#define	INCLUDED_NSHashTable_GNUstepBase_h

#import <GNUstepBase/GSVersionMacros.h>
#import <Foundation/NSHashTable.h>

#if	defined(__cplusplus)
extern "C" {
#endif

#if	OS_API_VERSION(GS_API_NONE,GS_API_LATEST)

@interface NSHashTable (GNUstepBase)
  /**
   * Adds each object contained in the given array that is not already
   * in the hash table.
   */
- (void)addObjectsFromArray: (NSArray*)array;
@end

#endif	/* OS_API_VERSION */

#if	defined(__cplusplus)
}
#endif

#endif	/* INCLUDED_NSHashTable_GNUstepBase_h */

