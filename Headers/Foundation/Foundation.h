// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: d52d9af274eb4b80e693cd0904b737ec7b6587d1 
// Date: 2015-07-07 22:31:41 +0000 
// ========== End of Keysight Technologies Notice ========== 
/*
   Global include file for the GNUstep Base Library.

   Copyright (C) 1997 Free Software Foundation, Inc.

   Written by:  Scott Christley <scottc@net-community.com>
   Date: Sep 1997
   
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

#ifndef __Foundation_h_GNUSTEP_BASE_INCLUDE
#define __Foundation_h_GNUSTEP_BASE_INCLUDE

#import	<GNUstepBase/GSVersionMacros.h>
#import	<objc/objc.h>

#import	<Foundation/FoundationErrors.h>
#import	<Foundation/NSObjCRuntime.h>
#import <GNUstepBase/GSConfig.h>
#import	<Foundation/NSDebug.h>
#import	<Foundation/NSObject.h>

#import	<Foundation/NSAffineTransform.h>
#import	<Foundation/NSArchiver.h>
#import	<Foundation/NSArray.h>
#import	<Foundation/NSAttributedString.h>
#import	<Foundation/NSAutoreleasePool.h>
#import	<Foundation/NSBundle.h>
#import	<Foundation/NSByteOrder.h>
#import	<Foundation/NSCache.h>
#import	<Foundation/NSCalendar.h>
#import	<Foundation/NSCalendarDate.h>
#import	<Foundation/NSCharacterSet.h>
#import	<Foundation/NSClassDescription.h>
#import	<Foundation/NSCoder.h>
#import	<Foundation/NSComparisonPredicate.h>
#import	<Foundation/NSCompoundPredicate.h>
#import	<Foundation/NSConnection.h>
#import	<Foundation/NSData.h>
#import	<Foundation/NSDateFormatter.h>
#import	<Foundation/NSDate.h>
#import	<Foundation/NSDecimalNumber.h>
#import	<Foundation/NSDictionary.h>
#import	<Foundation/NSDistantObject.h>
#import	<Foundation/NSDistributedLock.h>
#import	<Foundation/NSDistributedNotificationCenter.h>
#import	<Foundation/NSEnumerator.h>
#import	<Foundation/NSError.h>
#import	<Foundation/NSException.h>
#import	<Foundation/NSExpression.h>
#import	<Foundation/NSFileHandle.h>
#import	<Foundation/NSFileManager.h>
#import	<Foundation/NSFormatter.h>
#import	<Foundation/NSGarbageCollector.h>
#import	<Foundation/NSGeometry.h>
#import	<Foundation/NSHashTable.h>
#import	<Foundation/NSHost.h>
#import	<Foundation/NSHTTPCookie.h>
#import	<Foundation/NSHTTPCookieStorage.h>
#import	<Foundation/NSIndexPath.h>
#import	<Foundation/NSIndexSet.h>
#import	<Foundation/NSInvocation.h>
#import <Foundation/NSInvocationOperation.h>
#import	<Foundation/NSJSONSerialization.h>
#import	<Foundation/NSKeyedArchiver.h>
#import	<Foundation/NSKeyValueCoding.h>
#import	<Foundation/NSKeyValueObserving.h>
#import	<Foundation/NSLock.h>
#import	<Foundation/NSLocale.h>
#import	<Foundation/NSMapTable.h>
#import <Foundation/NSMetadata.h>
#import	<Foundation/NSMethodSignature.h>
#import	<Foundation/NSNotification.h>
#import	<Foundation/NSNotificationQueue.h>
#import	<Foundation/NSNetServices.h>
#import	<Foundation/NSNull.h>
#import	<Foundation/NSNumberFormatter.h>
#import	<Foundation/NSOperation.h>
#import	<Foundation/NSPathUtilities.h>
#import	<Foundation/NSPointerArray.h>
#import	<Foundation/NSPointerFunctions.h>
#import	<Foundation/NSPortCoder.h>
#import	<Foundation/NSPortMessage.h>
#import	<Foundation/NSPortNameServer.h>
#import	<Foundation/NSPredicate.h>
#import	<Foundation/NSProcessInfo.h>
#import	<Foundation/NSProtocolChecker.h>
#import	<Foundation/NSProxy.h>
#import	<Foundation/NSRange.h>
#import	<Foundation/NSRegularExpression.h>
#import	<Foundation/NSRunLoop.h>
#import	<Foundation/NSScanner.h>
#import	<Foundation/NSScriptWhoseTests.h>
#import	<Foundation/NSSerialization.h>
#import	<Foundation/NSSet.h>
#import	<Foundation/NSSortDescriptor.h>
#import	<Foundation/NSSpellServer.h>
#import	<Foundation/NSStream.h>
#import	<Foundation/NSString.h>
#import	<Foundation/NSTask.h>
#import	<Foundation/NSTextCheckingResult.h>
#import	<Foundation/NSThread.h>
#import	<Foundation/NSTimer.h>
#import	<Foundation/NSTimeZone.h>
#import	<Foundation/NSUndoManager.h>
#import	<Foundation/NSURLAuthenticationChallenge.h>
#import	<Foundation/NSURLCache.h>
#import	<Foundation/NSURLConnection.h>
#import	<Foundation/NSURLCredential.h>
#import	<Foundation/NSURLCredentialStorage.h>
#import	<Foundation/NSURLDownload.h>
#import	<Foundation/NSURLError.h>
#import	<Foundation/NSURL.h>
#import	<Foundation/NSURLHandle.h>
#import	<Foundation/NSURLProtectionSpace.h>
#import	<Foundation/NSURLProtocol.h>
#import	<Foundation/NSURLRequest.h>
#import	<Foundation/NSURLResponse.h>
#import	<Foundation/NSUserDefaults.h>
#import	<Foundation/NSUserNotification.h>
#import	<Foundation/NSUUID.h>
#import	<Foundation/NSValue.h>
#import	<Foundation/NSValueTransformer.h>
#import <Foundation/NSXMLDocument.h>
#import <Foundation/NSXMLDTD.h>
#import <Foundation/NSXMLDTDNode.h>
#import <Foundation/NSXMLElement.h>
#import <Foundation/NSXMLNode.h>
#import <Foundation/NSXMLNodeOptions.h>
#import	<Foundation/NSXMLParser.h>
#import	<Foundation/NSZone.h>

#endif /* __Foundation_h_GNUSTEP_BASE_INCLUDE */
