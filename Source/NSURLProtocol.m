// ========== Keysight Technologies Added Changes To Satisfy LGPL 2.x Section 2(a) Requirements ========== 
// Committed by: Marcian Lytwyn 
// Commit ID: e8c66e701f66e2137698230d75377ac7408ef299 
// Date: 2020-12-09 13:36:10 -0500 
// ========== End of Keysight Technologies Notice ========== 
/* Implementation for NSURLProtocol for GNUstep
   Copyright (C) 2006 Software Foundation, Inc.

   Written by:  Richard Frith-Macdonald <rfm@gnu.org>
   Date: 2006
   Parts (FTP and About in particular) based on later code by Nikolaus Schaller
   
   This file is part of the GNUstep Base Library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110 USA.
   */ 

#import "common.h"

#define	EXPOSE_NSURLProtocol_IVARS	1
#import "Foundation/NSError.h"
#import "Foundation/NSHost.h"
#import "Foundation/NSNotification.h"
#import "Foundation/NSRunLoop.h"
#import "Foundation/NSTimer.h"
#import "Foundation/NSUserDefaults.h"
#import "Foundation/NSValue.h"

#import "GSPrivate.h"
#import "GSURLPrivate.h"
#import "GNUstepBase/GSMime.h"
#import "GNUstepBase/GSTLS.h"
#import "GNUstepBase/NSData+GNUstepBase.h"
#import "GNUstepBase/NSStream+GNUstepBase.h"
#import "GNUstepBase/NSString+GNUstepBase.h"
#import "GNUstepBase/NSURL+GNUstepBase.h"

/* Define to 1 for experimental (net yet working) compression support
 */
#ifdef	USE_ZLIB
# undef	USE_ZLIB
#endif
#define	USE_ZLIB	0


#if	USE_ZLIB
#if	defined(HAVE_ZLIB_H)
#include	<zlib.h>

static void*
zalloc(void *opaque, unsigned nitems, unsigned size)
{
  return calloc(nitems, size);
}
static void
zfree(void *opaque, void *mem)
{
  free(mem);
}
#else
# undef	USE_ZLIB
# define	USE_ZLIB	0
#endif
#endif


static void
debugRead(id handle, int len, const unsigned char *ptr)
{
  int           pos;
  uint8_t       *hex;
  NSUInteger    hl;
  id            handlein = ((NO == [handle respondsToSelector:@selector(in)]) ?
				nil : [handle in]);

  hl = ((len + 2) / 3) * 4;
  hex = malloc(hl + 1);
  hex[hl] = '\0';
  GSPrivateEncodeBase64(ptr, (NSUInteger)len, hex);

  for (pos = 0; pos < len; pos++)
    {
      if (0 == ptr[pos])
        {
          NSData        *data;
          char          *esc;

          data = [[NSData alloc] initWithBytesNoCopy: (void*)ptr
                                              length: len
                                        freeWhenDone: NO];
          esc = [data escapedRepresentation: 0];

          NSLog(@"Read for %p %@ of %d bytes (escaped) - '%s'\n<[%s]>",
            handle, handlein, len, esc, hex); 
          free(esc);
          RELEASE(data);
          free(hex);
          return;
        }
    }
  NSLog(@"Read for %p %@ of %d bytes - '%*.*s'\n<[%s]>",
    handle, handlein, len, len, len, ptr, hex); 
  free(hex);
}
static void
debugWrite(id handle, int len, const unsigned char *ptr)
{
  int           pos;
  uint8_t       *hex;
  NSUInteger    hl;
  id            handleout = ((NO == [handle respondsToSelector:@selector(out)]) ?
				nil : [handle out]);

  hl = ((len + 2) / 3) * 4;
  hex = malloc(hl + 1);
  hex[hl] = '\0';
  GSPrivateEncodeBase64(ptr, (NSUInteger)len, hex);

  for (pos = 0; pos < len; pos++)
    {
      if (0 == ptr[pos])
        {
          NSData        *data;
          char          *esc;

          data = [[NSData alloc] initWithBytesNoCopy: (void*)ptr
                                              length: len
                                        freeWhenDone: NO];
          esc = [data escapedRepresentation: 0];
          NSLog(@"Write for %p %@ of %d bytes (escaped) - '%s'\n<[%s]>",
            handle, handleout, len, esc, hex); 
          free(esc);
          RELEASE(data);
          free(hex);
          return;
        }
    }
  NSLog(@"Write for %p %@ of %d bytes - '%*.*s'\n<[%s]>",
    handle, handleout, len, len, len, ptr, hex); 
  free(hex);
}

@interface	GSSocketStreamPair : NSObject
{
  NSInputStream		*ip;
  NSOutputStream	*op;
  NSHost		*host;
  uint16_t		port;
  NSDate		*expires;
  BOOL			ssl;
}
+ (void) purge: (NSNotification*)n;
- (void) cache: (NSDate*)when;
- (void) close;
- (NSDate*) expires;
- (id) initWithHost: (NSHost*)h port: (uint16_t)p forSSL: (BOOL)s;
- (NSInputStream*) inputStream;
- (NSOutputStream*) outputStream;
@end

@implementation	GSSocketStreamPair

static NSMutableArray	*pairCache = nil;
static NSLock		*pairLock = nil;

+ (void) initialize
{
  if (pairCache == nil)
    {
      /* No use trying to use a dictionary ... NSHost objects all hash
       * to the same value.
       */
      pairCache = [NSMutableArray new];
      [[NSObject leakAt: &pairCache] release];
      pairLock = [NSLock new];
      [[NSObject leakAt: &pairLock] release];
      /*  Purge expired pairs at intervals.
       */
      [[NSNotificationCenter defaultCenter] addObserver: self
	selector: @selector(purge:)
	name: @"GSHousekeeping" object: nil];
    }
}

+ (void) purge: (NSNotification*)n
{
  NSDate	*now = [NSDate date];
  unsigned	count;

  [pairLock lock];
  count = [pairCache count];
  while (count-- > 0)
    {
      GSSocketStreamPair	*p = [pairCache objectAtIndex: count];

      if ([[p expires] timeIntervalSinceDate: now] <= 0.0)
	{
	  [pairCache removeObjectAtIndex: count];
	}
    }
  [pairLock unlock];
}

- (void) cache: (NSDate*)when
{
  NSTimeInterval	ti = [when timeIntervalSinceNow];

  if (ti <= 0.0)
    {
      [self close];
      return;
    }
  NSAssert(ip != nil, NSGenericException);
  if (ti > 120.0)
    {
      ASSIGN(expires, [NSDate dateWithTimeIntervalSinceNow: 120.0]);
    }
  else
    { 
      ASSIGN(expires, when);
    }
  [pairLock lock];
  [pairCache addObject: self];
  [pairLock unlock];
}

- (void) close
{
  [ip setDelegate: nil];
  [op setDelegate: nil];
  [ip removeFromRunLoop: [NSRunLoop currentRunLoop]
		forMode: NSDefaultRunLoopMode];
  [op removeFromRunLoop: [NSRunLoop currentRunLoop]
		forMode: NSDefaultRunLoopMode];
  [ip close];
  [op close];
  DESTROY(ip);
  DESTROY(op);
}

- (void) dealloc
{
  [self close];
  DESTROY(host);
  DESTROY(expires);
  [super dealloc];
}

- (NSDate*) expires
{
  return expires;
}

- (id) init
{
  DESTROY(self);
  return nil;
}

- (id) initWithHost: (NSHost*)h port: (uint16_t)p forSSL: (BOOL)s;
{
  unsigned		count;
  NSDate		*now;

  now = [NSDate date];
  [pairLock lock];
  count = [pairCache count];
  while (count-- > 0)
    {
      GSSocketStreamPair	*pair = [pairCache objectAtIndex: count];

      if ([pair->expires timeIntervalSinceDate: now] <= 0.0)
	{
	  [pairCache removeObjectAtIndex: count];
	}
      else if (pair->port == p && pair->ssl == s && [pair->host isEqual: h])
	{
	  /* Found a match ... remove from cache and return as self.
	   */
	  DESTROY(self);
	  self = [pair retain];
	  [pairCache removeObjectAtIndex: count];
	  [pairLock unlock];
	  return self;
	}
    }
  [pairLock unlock];

  if ((self = [super init]) != nil)
    {
      [NSStream getStreamsToHost: host
			    port: port
		     inputStream: &ip
		    outputStream: &op];
      if (ip == nil || op == nil)
	{
	  DESTROY(self);
	  return nil;
	}
      ssl = s;
      port = p;
      host = [h retain];
      [ip retain];
      [op retain];
      if (ssl == YES)
        {
          [ip setProperty: NSStreamSocketSecurityLevelNegotiatedSSL
		   forKey: NSStreamSocketSecurityLevelKey];
          [op setProperty: NSStreamSocketSecurityLevelNegotiatedSSL
		   forKey: NSStreamSocketSecurityLevelKey];
        }
    }
  return self;
}

- (NSInputStream*) inputStream
{
  return ip;
}

- (NSOutputStream*) outputStream
{
  return op;
}

@end

@interface _NSAboutURLProtocol : NSURLProtocol
@end

@interface _NSFTPURLProtocol : NSURLProtocol
@end

@interface _NSFileURLProtocol : NSURLProtocol
@end

@interface _NSHTTPURLProtocol : NSURLProtocol
  <NSURLAuthenticationChallengeSender>
{
  GSMimeParser		*_parser;	// Parser handling incoming data
  unsigned		_parseOffset;	// Bytes of body loaded in parser.
  float			_version;	// The HTTP version in use.
  int			_statusCode;	// The HTTP status code returned.
  NSInputStream		*_body;		// for sending the body
  unsigned		_writeOffset;	// Request data to write
  NSData		*_writeData;	// Request bytes written so far
  BOOL			_complete;
  BOOL			_debug;
  BOOL			_isLoading;
  BOOL			_shouldClose;
  NSURLAuthenticationChallenge	*_challenge;
  NSURLCredential		*_credential;
  NSHTTPURLResponse		*_response;
}
@end

@interface _NSHTTPSURLProtocol : _NSHTTPURLProtocol
@end

@interface _NSDataURLProtocol : NSURLProtocol
@end


// Internal data storage
typedef struct {
  NSInputStream			*input;
  NSOutputStream		*output;
  NSCachedURLResponse		*cachedResponse;
  id <NSURLProtocolClient>	client;
  NSURLRequest			*request;
  unsigned char     *_inputBuffer;
  unsigned char     *_outputBuffer;
  NSTimer           *_timer;
#if	USE_ZLIB
  z_stream			z;		// context for decompress
  BOOL				compressing;	// are we compressing?
  BOOL				decompressing;	// are we decompressing?
  NSData			*compressed;	// only partially decompressed
#endif
} Internal;
 
#define	this          ((Internal*)(self->_NSURLProtocolInternal))
#define	inst          ((Internal*)(o->_NSURLProtocolInternal))
#define READ_BUFFER   (this->_inputBuffer)
#define WRITE_BUFFER  (this->_outputBuffer)

#define MAX_READ_BUFFER  BUFSIZ*64
#define MAX_WRITE_BUFFER MAX_READ_BUFFER

static NSMutableArray	*registered = nil;
static NSLock		*regLock = nil;
static Class		abstractClass = nil;
static Class		placeholderClass = nil;
static NSURLProtocol	*placeholder = nil;

@interface	NSURLProtocolPlaceholder : NSURLProtocol
@end
@implementation	NSURLProtocolPlaceholder
- (void) dealloc
{
  if (self == placeholder)
    {
      [self retain];
      return;
    }
  [super dealloc];
}
- (oneway void) release
{
  /* In a multi-threaded environment we could have two threads release the
   * class at the same time ... causing -dealloc to be called twice at the
   * same time, so that we can get an exception as we try to decrement the
   * retain count beyond zero.  To avoid this we make the placeholder be a
   * subclass whose -retain method prevents us even calling -dealoc in any
   * normal circumstances.
   */
  return;
}
@end

@implementation	NSURLProtocol

+ (id) allocWithZone: (NSZone*)z
{
  NSURLProtocol	*o;

  if ((self == abstractClass) && (z == 0 || z == NSDefaultMallocZone()))
    {
      /* Return a default placeholder instance to avoid the overhead of
       * creating and destroying instances of the abstract class.
       */
      o = placeholder;
    }
  else
    {
      /* Create and return an instance of the concrete subclass.
       */
      o = (NSURLProtocol*)NSAllocateObject(self, 0, z);
    }
  return o;
}

+ (void) initialize
{
  if (registered == nil)
    {
      abstractClass = [NSURLProtocol class];
      placeholderClass = [NSURLProtocolPlaceholder class];
      placeholder = (NSURLProtocol*)NSAllocateObject(placeholderClass, 0,
	NSDefaultMallocZone());
      [[NSObject leakAt: &placeholder] release];
      registered = [NSMutableArray new];
      [[NSObject leakAt: &registered] release];
      regLock = [NSLock new];
      [[NSObject leakAt: &regLock] release];
      [self registerClass: [_NSHTTPURLProtocol class]];
      [self registerClass: [_NSHTTPSURLProtocol class]];
      [self registerClass: [_NSFTPURLProtocol class]];
      [self registerClass: [_NSFileURLProtocol class]];
      [self registerClass: [_NSAboutURLProtocol class]];
      [self registerClass: [_NSDataURLProtocol class]];
    }
}

+ (id) propertyForKey: (NSString *)key inRequest: (NSURLRequest *)request
{
  return [request _propertyForKey: key];
}

+ (BOOL) registerClass: (Class)protocolClass
{
  if ([protocolClass isSubclassOfClass: [NSURLProtocol class]] == YES)
    {
      [regLock lock];
      [registered addObject: protocolClass];
      [regLock unlock];
      return YES;
    }
  return NO;
}

+ (void) setProperty: (id)value
	      forKey: (NSString *)key
	   inRequest: (NSMutableURLRequest *)request
{
  [request _setProperty: value forKey: key];
}

+ (void) unregisterClass: (Class)protocolClass
{
  [regLock lock];
  [registered removeObjectIdenticalTo: protocolClass];
  [regLock unlock];
}

- (NSCachedURLResponse *) cachedResponse
{
  return this->cachedResponse;
}

- (id <NSURLProtocolClient>) client
{
  return this->client;
}

- (void) dealloc
{
  if (this != 0)
    {
      [self stopLoading];
      if (this->input != nil)
	{
	  [this->input setDelegate: nil];
	  [this->output setDelegate: nil];
	  [this->input removeFromRunLoop: [NSRunLoop currentRunLoop]
				 forMode: NSDefaultRunLoopMode];
	  [this->output removeFromRunLoop: [NSRunLoop currentRunLoop]
				  forMode: NSDefaultRunLoopMode];
          [this->input close];
          [this->output close];
          DESTROY(this->input);
          DESTROY(this->output);
	}
      NSZoneFree([self zone], READ_BUFFER);
      NSZoneFree([self zone], WRITE_BUFFER);
      
      DESTROY(this->cachedResponse);
      DESTROY(this->request);
      DESTROY(this->client);
#if	USE_ZLIB
      if (this->compressing == YES)
	{
	  deflateEnd(&this->z);
	}
      else if (this->decompressing == YES)
	{
	  inflateEnd(&this->z);
	}
      DESTROY(this->compressed);
#endif
      NSZoneFree([self zone], this);
      _NSURLProtocolInternal = 0;
    }
  [super dealloc];
}

- (NSString*) description
{
  return [NSString stringWithFormat:@"%@ %@",
    [super description], this ? (id)this->request : nil];
}

- (id) init
{
  if ((self = [super init]) != nil)
    {
      Class	c = object_getClass(self);

      if (c != abstractClass && c != placeholderClass)
	{
	  _NSURLProtocolInternal = NSZoneCalloc([self zone],
	    1, sizeof(Internal));
	}
    }
  return self;
}

- (id) initWithRequest: (NSURLRequest *)request
	cachedResponse: (NSCachedURLResponse *)cachedResponse
		client: (id <NSURLProtocolClient>)client
{
  Class	c = object_getClass(self);

  if (c == abstractClass || c == placeholderClass)
    {
      unsigned	count;

      DESTROY(self);
      [regLock lock];
      count = [registered count];
      while (count-- > 0)
        {
	  Class	proto = [registered objectAtIndex: count];

	  if ([proto canInitWithRequest: request] == YES)
	    {
	      self = [proto alloc];
	      break;
	    }
	}
      [regLock unlock];
      return [self initWithRequest: request
		    cachedResponse: cachedResponse
			    client: client];
    }
  if ((self = [self init]) != nil)
    {
      this->request = [request copy];
      this->cachedResponse = RETAIN(cachedResponse);
      this->client = RETAIN(client);
      READ_BUFFER = NSZoneCalloc([self zone], 1, MAX_READ_BUFFER);
      WRITE_BUFFER = NSZoneCalloc([self zone], 1, MAX_WRITE_BUFFER);
    }
  return self;
}

- (NSURLRequest *) request
{
  return this->request;
}

@end

@implementation	NSURLProtocol (Private)

+ (Class) _classToHandleRequest:(NSURLRequest *)request
{
  Class protoClass = nil;
  int count;
  [regLock lock];

  count = [registered count];
  while (count-- > 0)
    {
      Class	proto = [registered objectAtIndex: count];

      if ([proto canInitWithRequest: request] == YES)
	{
	  protoClass = proto;
	  break;
}
    }
  [regLock unlock];
  return protoClass;
}

- (NSDictionary*) _userInfoForErrorCode: (NSUInteger) errorCode description: (NSString*) description host: (NSHost*)host
{
  return [NSDictionary dictionaryWithObjectsAndKeys:
          [this->request URL],  NSURLErrorFailingURLErrorKey,
          host,                 NSErrorFailingURLStringKey,
          description,          NSLocalizedDescriptionKey,
          description,          NSLocalizedFailureReasonErrorKey,
          nil];
}

- (NSDictionary*) _userInfoForErrorCode: (NSUInteger) errorCode description: (NSString*) description
{
  NSURL   *url  = [this->request URL];
  NSHost	*host = [NSHost hostWithName: [url host]];
  //int	port = [[url port] intValue];
  
  if (host == nil)
  {
    host = [NSHost hostWithAddress: [url host]];	// try dotted notation
  }
  if (host == nil)
  {
    host = [NSHost hostWithAddress: @"127.0.0.1"];	// final default
  }
  
  if (host)
    return [self _userInfoForErrorCode: errorCode description: description host: host];

  return [NSDictionary dictionaryWithObjectsAndKeys:
          [this->request URL],                  NSURLErrorFailingURLErrorKey,
          [[this->request URL] absoluteString], NSErrorFailingURLStringKey,
          description,                          NSLocalizedDescriptionKey,
          description,                          NSLocalizedFailureReasonErrorKey,
          nil];
}

- (NSDictionary*) _userInfoForErrorCode: (NSUInteger) errorCode
{
  return [NSDictionary dictionaryWithObjectsAndKeys:
          [this->request URL],                  @"URL",
          [[this->request URL] path],           @"path",
          [this->request URL],                  NSURLErrorFailingURLErrorKey,
          [[this->request URL] absoluteString], NSErrorFailingURLStringKey,
          @"unknown error occurred",            NSLocalizedDescriptionKey,
          @"unknown error occurred",            NSLocalizedFailureReasonErrorKey,
          nil];
}

@end

@implementation	NSURLProtocol (Subclassing)

+ (BOOL) canInitWithRequest: (NSURLRequest *)request
{
  [self subclassResponsibility: _cmd];
  return NO;
}

+ (NSURLRequest *) canonicalRequestForRequest: (NSURLRequest *)request
{
  return request;
}

+ (BOOL) requestIsCacheEquivalent: (NSURLRequest *)a
			toRequest: (NSURLRequest *)b
{
  a = [self canonicalRequestForRequest: a];
  b = [self canonicalRequestForRequest: b];
  return [a isEqual: b];
}

- (void) startLoading
{
  [self subclassResponsibility: _cmd];
}

- (void) stopLoading
{
  [self subclassResponsibility: _cmd];
}

@end






@implementation _NSHTTPURLProtocol

+ (BOOL) canInitWithRequest: (NSURLRequest*)request
{
  return [[[request URL] scheme] isEqualToString: @"http"];
}

+ (NSURLRequest*) canonicalRequestForRequest: (NSURLRequest*)request
{
  return request;
}

- (void) cancelAuthenticationChallenge: (NSURLAuthenticationChallenge*)c
{
  if (c == _challenge)
    {
      DESTROY(_challenge);	// We should cancel the download
    }
}

- (void) continueWithoutCredentialForAuthenticationChallenge:
  (NSURLAuthenticationChallenge*)c
{
  if (c == _challenge)
    {
      DESTROY(_credential);	// We download the challenge page
    }
}

- (void) dealloc
{
  RELEASE(_parser);     // received headers
  RELEASE(_body);       // for sending the body
  RELEASE(_response);
  RELEASE(_credential);
  [super dealloc];
}

- (void) _timedout: (NSTimer*)timer
{
  if (_debug)
  {
    NSWarnMLog(@"request timed out: %@ after %f secs", this->request, [[timer userInfo] doubleValue]);
  }
  NSTimeInterval timeInterval = [[timer userInfo] doubleValue]; // the original timeout value used...
  NSString       *description = [NSString stringWithFormat: @"Timeout: Host failed to respond after %.0f seconds",timeInterval];
  NSDictionary   *userinfo    = [self _userInfoForErrorCode: 0 description: description];
  NSError        *error       = [NSError errorWithDomain: @"Timeout on connection"
                                                    code: 0
                                                userInfo: userinfo];
  [self stopLoading];
  [this->client URLProtocol: self didFailWithError: error];
  DESTROY(this->client);
}

- (NSTimeInterval) _timeInterval
{
  static const NSTimeInterval DefaultConnectionTimeout = 60.0;
  NSTimeInterval timeout = [this->request timeoutInterval];
  if (timeout <= 0)
  {
    // Check defaults next for a value...
    if ([[NSUserDefaults standardUserDefaults] objectForKey: @"GSURLProtocolConnectionTimeout"])
    {
      timeout = [[NSUserDefaults standardUserDefaults] doubleForKey: @"GSURLProtocolConnectionTimeout"];
      if (timeout <= 0)
      {
        timeout = DefaultConnectionTimeout;
      }
    }
    else
    {
      timeout = DefaultConnectionTimeout;
    }
  }
  
  return timeout;
}

- (void) _stopTimer
{
  if ((NULL != this) && (this->_timer))
  {
    [this->_timer invalidate];
    this->_timer = nil; // We hold a weak reference...
  }
}

- (void) _startTimer
{
  // First stop any current timer...
  [self _stopTimer];
  
  // TESTPLANT-MAL-090892017: Start a timer for this operation to avoid hangs...
  NSTimeInterval timeout = [self _timeInterval];
  
  // Log the timeout value...
  if (_debug)
    NSWarnMLog(@"req: %@ using connection timeout: %f", this->request, timeout);
  
  // Start and schedule the timer...weak reference to avoid circular...
  this->_timer = [NSTimer scheduledTimerWithTimeInterval: timeout
                                                  target: self
                                                selector: @selector(_timedout:)
                                                userInfo: [NSNumber numberWithDouble: timeout]
                                                 repeats: NO];
}

- (void) startLoading
{
  static NSDictionary *methods = nil;

  _debug = GSDebugSet(@"NSURLProtocol");
  if (YES == [this->request _debug]) _debug = YES;

  if (methods == nil)
    {
      methods = [[NSDictionary alloc] initWithObjectsAndKeys: 
	self, @"HEAD",
	self, @"GET",
	self, @"POST",
	self, @"PATCH",
	self, @"PUT",
	self, @"DELETE",
	self, @"TRACE",
	self, @"OPTIONS",
	self, @"CONNECT",
	nil];
      }
  if ([methods objectForKey: [this->request HTTPMethod]] == nil)
    {
      NSLog(@"Invalid HTTP Method: %@", this->request);
      [self stopLoading];
      [this->client URLProtocol: self didFailWithError:
       [NSError errorWithDomain: @"Invalid HTTP Method"
                           code: 0
                       userInfo: [self _userInfoForErrorCode: 0]]];
      DESTROY(this->client);
      return;
    }
  if (_isLoading == YES)
    {
      NSLog(@"startLoading when load in progress");
      return;
    }

  _statusCode = 0;	/* No status returned yet.	*/
  _isLoading = YES;
  _complete = NO;

  /* Perform a redirect if the path is empty.
   * As per MacOs-X documentation.
   */
  if ([[[this->request URL] fullPath] length] == 0)
    {
      NSString		*s = [[this->request URL] absoluteString];
      NSURL		*url;

      if ([s rangeOfString: @"?"].length > 0)
        {
	  s = [s stringByReplacingString: @"?" withString: @"/?"];
	}
      else if ([s rangeOfString: @"#"].length > 0)
        {
	  s = [s stringByReplacingString: @"#" withString: @"/#"];
	}
      else
        {
          s = [s stringByAppendingString: @"/"];
	}
      url = [NSURL URLWithString: s];
      if (url == nil)
	{
	  NSError	*e;

	  e = [NSError errorWithDomain: @"Invalid redirect request"
				  code: 0
			      userInfo: [self _userInfoForErrorCode: 0]];
	  [self stopLoading];
	  [this->client URLProtocol: self didFailWithError: e];
    DESTROY(this->client);
	}
      else
	{
	  NSMutableURLRequest	*request;

	  request = AUTORELEASE([this->request mutableCopy]);
	  [request setURL: url];
          // This invocation may end up detroying us so need to retain/autorelease...
          AUTORELEASE(RETAIN(self));
    [this->client URLProtocol: self
       wasRedirectedToRequest: request
             redirectResponse: nil];
	}
      if (NO == _isLoading)
        {
	  return;	// Loading cancelled
	}
      if (nil != this->input)
	{
	  return;	// Following redirection
	}
      // Fall through to continue original connect.
    }

  if (0 && this->cachedResponse)
    {
    }
  else
    {
      NSURL	*url = [this->request URL];
      NSHost	*host = [NSHost hostWithName: [url host]];
      int	port = [[url port] intValue];

      _parseOffset = 0;
      DESTROY(_parser);

      if (host == nil)
        {
	  host = [NSHost hostWithAddress: [url host]];	// try dotted notation
	}
      if (host == nil)
        {
	  host = [NSHost hostWithAddress: @"127.0.0.1"];	// final default
	}
      if (port == 0)
        {
	  // default if not specified
	  port = [[url scheme] isEqualToString: @"https"] ? 443 : 80;
	}

      [NSStream getStreamsToHost: host
			    port: port
		     inputStream: &this->input
		    outputStream: &this->output];
      if (!this->input || !this->output)
	{
	  if (_debug == YES)
	    {
	      NSLog(@"%@ did not create streams for %@:%@",
		self, host, [url port]);
	    }
	  [self stopLoading];
	  [this->client URLProtocol: self didFailWithError:
           [NSError errorWithDomain: @"can't connect" code: 0
                           userInfo: [self _userInfoForErrorCode: 0 description: @"can't find host" host: host]]];
    DESTROY(this->client);
	  return;
	}
      [this->input retain];
      [this->output retain];
      if ([[url scheme] isEqualToString: @"https"] == YES)
        {
          static NSArray        *keys;
          NSUInteger            count;

          [this->input setProperty: NSStreamSocketSecurityLevelNegotiatedSSL
                            forKey: NSStreamSocketSecurityLevelKey];
          [this->output setProperty: NSStreamSocketSecurityLevelNegotiatedSSL
                             forKey: NSStreamSocketSecurityLevelKey];
          if (nil == keys)
            {
              keys = [[NSArray alloc] initWithObjects:
                GSTLSCAFile,
                GSTLSCertificateFile,
                GSTLSCertificateKeyFile,
                GSTLSCertificateKeyPassword,
                GSTLSDebug,
                GSTLSPriority,
                GSTLSRemoteHosts,
                GSTLSRevokeFile,
                GSTLSServerName,
                GSTLSVerify,
                nil];
            }
          count = [keys count];
          while (count-- > 0)
            {
              NSString      *key = [keys objectAtIndex: count];
              NSString      *str = [this->request _propertyForKey: key];

              if (nil != str)
                {
                  [this->output setProperty: str forKey: key];
                }
            }
          /* If there is no value set for the server name, and the host in the
           * URL is a domain name rather than an address, we use that.
           */
          if (nil == [this->output propertyForKey: GSTLSServerName])
            {
              NSString  *host = [url host];
              unichar   c;

              c = [host length] == 0 ? 0 : [host characterAtIndex: 0];
              if (c != 0 && c != ':' && !isdigit(c))
                {
                  [this->output setProperty: host forKey: GSTLSServerName];
                }
            }
          if (_debug) [this->output setProperty: @"YES" forKey: GSTLSDebug];
        }
      [this->input setDelegate: self];
      [this->output setDelegate: self];
      [this->input scheduleInRunLoop: [NSRunLoop currentRunLoop]
			     forMode: NSDefaultRunLoopMode];
      [this->output scheduleInRunLoop: [NSRunLoop currentRunLoop]
			      forMode: NSDefaultRunLoopMode];
      [this->input open];
      [this->output open];
      
      // TESTPLANT-MAL-090892017: Start a timer for this operation to avoid hangs...
      [self _startTimer];
    }
}

- (void) stopLoading
{
  if (_debug == YES)
    {
      NSWarnMLog(@"%@ stopLoading", self);
    }
  _isLoading = NO;
  DESTROY(_writeData);
  if (this->input != nil)
    {
      [this->input setDelegate: nil];
      [this->output setDelegate: nil];
      [this->input removeFromRunLoop: [NSRunLoop currentRunLoop]
			     forMode: NSDefaultRunLoopMode];
      [this->output removeFromRunLoop: [NSRunLoop currentRunLoop]
			      forMode: NSDefaultRunLoopMode];
      [this->input close];
      [this->output close];
      DESTROY(this->input);
      DESTROY(this->output);
      [self _stopTimer];
    }
}

- (void) _didLoad: (NSData*)d
{
  [this->client URLProtocol: self didLoadData: d];
}

- (void) _got: (NSStream*)stream
{
  if (_debug)
    {
      NSWarnMLog(@"[MethodEntry] _got: Entering with stream=%p streamStatus=%ld hasBytesAvailable=%d",
                 stream, (long)[stream streamStatus], (int)[(NSInputStream*)stream hasBytesAvailable]);
    }

  int       readCount = -1;
  NSError  *e;
  NSData   *d;
  BOOL      wasInHeaders = NO;
  int       totalRead = 0;

  if (_debug)
    {
      NSWarnMLog(@"[_got] About to start read loop. totalRead=%d, hasBytesAvailable=%d",
                 totalRead, (int)[(NSInputStream *)stream hasBytesAvailable]);
    }

  NSStreamStatus sstat = [stream streamStatus];
  while ((totalRead < MAX_READ_BUFFER)
         && (([(NSInputStream *)stream hasBytesAvailable]) || sstat == NSStreamStatusReading))
    {
      readCount = [(NSInputStream *)stream read: &READ_BUFFER[totalRead]
                                      maxLength: (MAX_READ_BUFFER - totalRead)];
      sstat = [stream streamStatus];

      if (_debug)
        {
          NSWarnMLog(@"[ReadLoop] readCount=%d, totalRead(before)=%d, newStreamStatus=%ld",
                     readCount, totalRead, (long)sstat);
        }

#if defined(_WIN32)
      // Windows-specific logic
      if ([[[this->request valueForHTTPHeaderField:@"Tcp-Wait-For-Server-Close"] lowercaseString] isEqualToString:@"true"])
        {
          if (_debug)
            {
              NSWarnMLog(@"[Win32] Using Tcp-Wait-For-Server-Close logic");
            }
          if (readCount < 0)
            {
              int wsaErr = WSAGetLastError();
              if (wsaErr == WSAEWOULDBLOCK)
                {
                  if (_debug)
                    {
                      NSWarnMLog(@"[Win32] readCount < 0 with WSAEWOULDBLOCK => continuing");
                    }
                  sstat = NSStreamStatusReading;
                  continue;
                }
              else
                {
                  if (_debug)
                    {
                      NSWarnMLog(@"[Win32] readCount < 0 => real error => break");
                    }
                  break;
                }
            }
          else if (readCount == 0)
            {
              // EOF
              if (_debug)
                {
                  NSWarnMLog(@"[Win32] readCount=0 => EOF => break from read loop");
                }
              break;
            }
        }
      else
        {
          if (readCount <= 0)
            {
              if (_debug)
                {
                  NSWarnMLog(@"[Win32] readCount <= 0 => break");
                }
              break;
            }
        }
#else
      // Non-Windows: break on error or EOF
      if (readCount <= 0)
        {
          if (_debug)
            {
              NSWarnMLog(@"[Unix] readCount <= 0 => break from read loop");
            }
          break;
        }
#endif

      totalRead += readCount;

      if (_debug)
        {
          NSWarnMLog(@"[ReadLoop] after read => totalRead=%d (accumulated bytes)", totalRead);
        }
    } // end while

  if (_debug)
    {
      NSWarnMLog(@"[ReadLoopDone] Exited read loop => readCount=%d, totalRead=%d, final streamStatus=%ld",
                 readCount, totalRead, (long)[stream streamStatus]);
    }

  // If we failed to read anything at all
  if ((readCount <= 0) && (totalRead == 0))
    {
      if (_debug)
        {
          NSWarnMLog(@"[_got] readCount <= 0 and totalRead=0 => no data read => checking stream status=%ld",
                     (long)[stream streamStatus]);
        }

      if ([stream streamStatus] == NSStreamStatusError)
        {
          e = [stream streamError];
          if (_debug)
            {
              NSWarnMLog(@"[_got] stream error => %@", e);
            }
          [self stopLoading];
          [this->client URLProtocol:self didFailWithError:e];
          DESTROY(this->client);

          if (_debug)
            {
              NSWarnMLog(@"[MethodExit] _got: returning early after stream error => no data read");
            }
          return;
        }

      if (_debug)
        {
          NSWarnMLog(@"[_got] readCount=%d totalRead=%d => returning early => no data. Not an error stream status.",
                     readCount, totalRead);
        }

      // No error state, no data => just return
      if (_debug)
        {
          NSWarnMLog(@"[MethodExit] _got: returning => no data read, no error => waiting for more events");
        }
      return;
    }

  readCount = totalRead;

  if (_debug)
    {
      NSWarnMLog(@"[_got] readCount now set to totalRead=%d => calling debugRead", readCount);
      debugRead(self, readCount, READ_BUFFER);
    }

  // Create parser if needed
  if (_parser == nil)
    {
      if (_debug)
        {
          NSWarnMLog(@"[_got] Creating new GSMimeParser => setIsHttp");
        }
      _parser = [GSMimeParser new];
      [_parser setIsHttp];
    }

  wasInHeaders = [_parser isInHeaders];
  d = [NSData dataWithBytes: READ_BUFFER length: readCount];

  if (_debug)
    {
      NSWarnMLog(@"[_got] Passing %d bytes to parser => wasInHeaders=%d", readCount, wasInHeaders);
    }

  // Parse the data
  if ([_parser parse:d] == NO && (_complete = [_parser isComplete]) == NO)
    {
      if (_debug)
        {
          NSWarnMLog(@"[_got] HTTP parse failure => parserState=%@", _parser);
        }
      e = [NSError errorWithDomain:@"parse error"
                              code:0
                          userInfo:nil];
      [self stopLoading];
      [this->client URLProtocol:self didFailWithError:e];
      DESTROY(this->client);

      if (_debug)
        {
          NSWarnMLog(@"[MethodExit] _got: returning => parse error");
        }
      return;
    }
  else
    {
      BOOL           isInHeaders = [_parser isInHeaders];
      GSMimeDocument *document   = [_parser mimeDocument];
      unsigned       bodyLength;

      if (_debug)
        {
          NSWarnMLog(@"[_got] Parser done => document=%@", document);
        }

      _complete = [_parser isComplete];
      NSStreamStatus currentStatus = [stream streamStatus];
      if ((_complete == NO) && (currentStatus == NSStreamStatusAtEnd))
        {
          if (_debug)
            {
              NSWarnMLog(@"[_got] premature stream status=AtEnd => forcing _complete=YES");
            }
          _complete = YES;
        }

      if (_debug)
        {
          NSWarnMLog(@"[_got] after parse => _complete=%d wasInHeaders=%d isInHeaders=%d (streamStatus=%ld)",
                     _complete, wasInHeaders, isInHeaders, (long)currentStatus);
        }

      // Just finished reading headers?
      if (wasInHeaders == YES && isInHeaders == NO)
        {
          // handle response headers, status codes, etc.
          if (_debug)
            {
              NSWarnMLog(@"[_got] done reading headers => building NSHTTPURLResponse");
            }
          GSMimeHeader *info = [document headerNamed:@"http"];
          int          len   = -1;
          NSString    *ct, *st, *s;

          _version = [[info value] floatValue];
          if (_version < 1.1)
            {
              _shouldClose = YES;
            }
          else if ((s = [[document headerNamed:@"connection"] value]) != nil
                   && [s caseInsensitiveCompare:@"close"] == NSOrderedSame)
            {
              _shouldClose = YES;
            }
          else
            {
              _shouldClose = NO;
            }

          s = [info objectForKey:NSHTTPPropertyStatusCodeKey];
          _statusCode = [s intValue];

          s = [[document headerNamed:@"content-length"] value];
          if ([s length] > 0)
            {
              len = [s intValue];
            }

          if (_debug)
            {
              NSWarnMLog(@"[_got] statusCode=%d => content-length=%d", _statusCode, len);
            }

          NSString *reasonPhrase = [info objectForKey:NSHTTPPropertyStatusReasonKey];
          GSMimeHeader *contentTypeHdr = [document headerNamed:@"content-type"];
          ct = [document contentType];
          st = [document contentSubtype];
          if (ct && st)
            {
              ct = [ct stringByAppendingFormat:@"/%@", st];
            }
          else
            {
              ct = nil;
            }

          _response = [[NSHTTPURLResponse alloc]
                       initWithURL:[this->request URL]
                       MIMEType:ct
                       expectedContentLength:len
                       textEncodingName:[contentTypeHdr parameterForKey:@"charset"]];
          [_response _setStatusCode:_statusCode text:reasonPhrase];
          [document deleteHeaderNamed:@"http"];
          [_response _setHeaders:[document allHeaders]];

          if (_debug)
            {
              NSWarnMLog(@"[_got] [document allHeaders]: %@", [document allHeaders]);
            }

          // Decide if we’re done yet
          if (_statusCode == 204 || _statusCode == 304 || _statusCode == 404)
            {
              if (_debug)
                {
                  NSWarnMLog(@"[_got] => no body expected => forcing _complete=YES");
                }
              _complete = YES;
            }
          else if (_complete == NO && [d length] == 0)
            {
              if (_debug)
                {
                  NSWarnMLog(@"[_got] => got EOF with no body => forcing _complete=YES");
                }
              _complete = YES;
            }

          // etc. check for 401, 3xx redirect, cookies...
          if (_debug)
            {
              NSWarnMLog(@"[_got] done analyzing headers => calling didReceiveResponse if no other blocks");
            }
          // ...
        } // end if (wasInHeaders && !isInHeaders)

      if (_debug)
        {
          NSWarnMLog(@"[_got] final check => _complete=%d d-length=%ld", _complete, (long)[d length]);
        }

      if (_complete == YES)
        {
          if (_debug)
            {
              NSWarnMLog(@"[_got] => finishing up => removing streams from runloop, etc.");
            }

          [this->input removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
          [this->output removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];

          if (_shouldClose == YES)
            {
              if (_debug)
                {
                  NSWarnMLog(@"[_got] => shouldClose => closing input/output streams & stopping timer");
                }
              [this->input setDelegate:nil];
              [this->output setDelegate:nil];
              [this->input close];
              [this->output close];
              DESTROY(this->input);
              DESTROY(this->output);
              [self _stopTimer];
            }

          if (_isLoading == YES)
            {
              d = [_parser data];
              bodyLength = [d length];
              if (bodyLength > _parseOffset)
                {
                  if (_parseOffset > 0)
                    {
                      d = [d subdataWithRange:NSMakeRange(_parseOffset, bodyLength - _parseOffset)];
                    }
                  _parseOffset = bodyLength;
                  if (_debug)
                    {
                      NSWarnMLog(@"[_got] calling _didLoad => final chunk size=%ld", (long)[d length]);
                    }
                  [self _didLoad:d];
                }

              if (_isLoading == YES)
                {
                  if (_debug)
                    {
                      NSWarnMLog(@"[_got] => calling URLProtocolDidFinishLoading => success path");
                    }
                  _isLoading = NO;
                  [this->client URLProtocolDidFinishLoading:self];
                  DESTROY(this->client);
                }
            }
        }
      else if (_isLoading == YES && _statusCode != 401)
        {
          // Possibly partial data => call didLoad
          if ([_parser isInBody])
            {
              d = [_parser data];
              bodyLength = [d length];
              if (bodyLength > _parseOffset)
                {
                  if (_parseOffset > 0)
                    {
                      d = [d subdataWithRange:NSMakeRange(_parseOffset, bodyLength - _parseOffset)];
                    }
                  _parseOffset = bodyLength;
                  if (_debug)
                    {
                      NSWarnMLog(@"[_got] partial => calling _didLoad => chunk size=%ld", (long)[d length]);
                    }
                  [self _didLoad:d];
                }
            }

          // HEAD => done after headers
          if ([[this->request HTTPMethod] isEqualToString:@"HEAD"] && (isInHeaders == NO))
            {
              if (_debug)
                {
                  NSWarnMLog(@"[_got] => HEAD request => finishing early => calling DidFinishLoading");
                }
              _isLoading = NO;
              [this->client URLProtocolDidFinishLoading:self];
              DESTROY(this->client);
            }
        }

      // If no progress but parse is incomplete => fail
      if (_complete == NO && readCount == 0 && _isLoading == YES)
        {
          if (_debug)
            {
              NSWarnMLog(@"[_got] => readCount=0 => parse incomplete => failWithError => incomplete data");
            }
          [self stopLoading];
          NSError *incompleteErr = [NSError errorWithDomain:@"receive incomplete"
                                                       code:0
                                                   userInfo:nil];
          [this->client URLProtocol:self didFailWithError:incompleteErr];
          DESTROY(this->client);
        }
    }

  if (_debug)
    {
      NSWarnMLog(@"[MethodExit] _got: done => returning from method with stream=%p", stream);
    }
}


- (void) stream: (NSStream*) stream handleEvent: (NSStreamEvent) event
{
  /* Make sure no action triggered by anything else destroys us prematurely.
   */
  IF_NO_GC([[self retain] autorelease];)

  if (_debug)
    {
      NSWarnMLog(@"stream: %@ handleEvent: %p for: %@ (ip %p, op %p)",
            stream, (void*)event, self, this->input, this->output);
    }
  
  if (stream == this->input) 
    {- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)event
{
  if (_debug)
    {
      NSWarnMLog(@"[MethodEntry] stream:%p handleEvent=0x%lx (input? %d, output? %d)",
                 stream,
                 (unsigned long)event,
                 (stream == this->input),
                 (stream == this->output));
    }

  // -----------------------------------------------------------------------
  // Handle the INPUT stream case
  // -----------------------------------------------------------------------
  if (stream == this->input)
    {
      if (_debug)
        {
          NSWarnMLog(@"[InputStream] => event=0x%lx => analyzing input event", (unsigned long)event);
        }

      switch (event)
        {
          case NSStreamEventHasBytesAvailable:
          case NSStreamEventEndEncountered:
            // We treat EndEncountered similarly to "HasBytesAvailable" in this snippet
            if (_debug)
              {
                NSWarnMLog(@"[InputStream] => event=0x%lx => calling _got: to read data", (unsigned long)event);
              }
            [self _got: stream];
            if (_debug)
              {
                NSWarnMLog(@"[InputStream] => returned from _got: => done with this event");
              }
            return;

          case NSStreamEventOpenCompleted:
            if (_debug)
              {
                NSWarnMLog(@"[InputStream] => NSStreamEventOpenCompleted => HTTP input stream opened");
                NSWarnMLog(@"self=%@ HTTP input stream opened", self);
              }
            return;

          default:
            // We handle unexpected events below
            break;
        }
    }

  // -----------------------------------------------------------------------
  // Handle the OUTPUT stream case
  // -----------------------------------------------------------------------
  else if (stream == this->output)
    {
      if (_debug)
        {
          NSWarnMLog(@"[OutputStream] => event=0x%lx => analyzing output event", (unsigned long)event);
        }

      switch(event)
        {
          // ---------------------------------------------------------------
          // When the output stream is first opened, we build + send the
          // initial request line & headers
          // ---------------------------------------------------------------
          case NSStreamEventOpenCompleted:
            {
              if (_debug)
                {
                  NSWarnMLog(@"[OutputStream] => NSStreamEventOpenCompleted => building HTTP request data");
                  NSWarnMLog(@"%@ HTTP output stream opened", self);
                }
              DESTROY(_writeData);
              _writeOffset = 0;

              NSMutableData *m;
              NSDictionary  *d;
              NSEnumerator  *eDict;
              NSString      *s;
              NSURL         *u;
              int            l;

              // Decide if we are streaming body or not
              if ([this->request HTTPBodyStream] == nil)
                {
                  // Not streaming
                  l = [[this->request HTTPBody] length];
                  _version = 1.1;
                }
              else
                {
                  // Using a streaming body => set version=1.0 (some logic)
                  l = -1;
                  _version = 1.0;
                  // Possibly: _shouldClose = YES; (commented out in your snippet)
                }

              m = [[NSMutableData alloc] initWithCapacity:1024];

              // Build the request line:
              // => "METHOD /path?query HTTP/version\r\n"
              [m appendData:[[this->request HTTPMethod]
                             dataUsingEncoding:NSASCIIStringEncoding]];
              [m appendBytes:" " length:1];
              u = [this->request URL];
              // Full path with percent escapes
              s = [[u fullPath] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
              if ([s hasPrefix:@"/"] == NO)
                {
                  [m appendBytes:"/" length:1];
                }
              [m appendData:[s dataUsingEncoding:NSASCIIStringEncoding]];

              // If there's a query?
              NSString *qs = [u query];
              if ([qs length] > 0)
                {
                  [m appendBytes:"?" length:1];
                  [m appendData:[qs dataUsingEncoding:NSASCIIStringEncoding]];
                }

              s = [NSString stringWithFormat:@" HTTP/%0.1f\r\n", _version];
              [m appendData:[s dataUsingEncoding:NSASCIIStringEncoding]];

              // Append all HTTP headers
              d = [this->request allHTTPHeaderFields];
              eDict = [d keyEnumerator];
              while ((s = [eDict nextObject]) != nil)
                {
                  GSMimeHeader *h = [[GSMimeHeader alloc]
                                     initWithName:s
                                     value:[d objectForKey:s]
                                     parameters:nil];
                  [m appendData:[h rawMimeDataPreservingCase:YES foldedAt:0]];
                  RELEASE(h);
                }

              // If this is a POST but no Content-Type => add one
              if ([[this->request HTTPMethod] isEqual:@"POST"]
                  && [this->request valueForHTTPHeaderField:@"Content-Type"] == nil)
                {
                  static char *ct = "Content-Type: application/x-www-form-urlencoded\r\n";
                  [m appendBytes:ct length:strlen(ct)];
                }

              // If no Host header => add one
              if ([this->request valueForHTTPHeaderField:@"Host"] == nil)
                {
                  NSString *schemeStr = [u scheme];
                  id p = [u port];
                  id h = [u host];
                  if (h == nil)
                    {
                      h = @""; // must send an empty host header
                    }
                  if (([schemeStr isEqualToString:@"http"] && [p intValue] == 80) ||
                      ([schemeStr isEqualToString:@"https"] && [p intValue] == 443))
                    {
                      // omit the port if it's the default
                      p = nil;
                    }
                  if (p == nil)
                    {
                      s = [NSString stringWithFormat:@"Host: %@\r\n", h];
                    }
                  else
                    {
                      s = [NSString stringWithFormat:@"Host: %@:%@\r\n", h, p];
                    }
                  [m appendData:[s dataUsingEncoding:NSASCIIStringEncoding]];
                }

              // If we have a known content length => add a header if missing
              if (l >= 0 && [this->request valueForHTTPHeaderField:@"Content-Length"] == nil)
                {
                  s = [NSString stringWithFormat:@"Content-Length: %d\r\n", l];
                  [m appendData:[s dataUsingEncoding:NSASCIIStringEncoding]];
                }

              // End of headers => \r\n
              [m appendBytes:"\r\n" length:2];
              _writeData = m;

              // Fall through to handle the actual writing in HasSpaceAvailable
            }
            // *** FALLTHROUGH ***

          // ---------------------------------------------------------------
          // If we can write => flush out _writeData or body
          // ---------------------------------------------------------------
          case NSStreamEventHasSpaceAvailable:
            {
              if (_debug)
                {
                  NSWarnMLog(@"[OutputStream] => NSStreamEventHasSpaceAvailable => writing request data (if any)");
                }
              int written;
              BOOL sent = NO;

              // If we have _writeData => flush it
              if (_writeData != nil)
                {
                  const unsigned char *bytes = [_writeData bytes];
                  NSUInteger len = [_writeData length];

                  if (_debug)
                    {
                      NSWarnMLog(@"[OutputStream] => writing _writeData => total len=%lu, current offset=%ld",
                                 (unsigned long)len, (long)_writeOffset);
                    }

                  written = [this->output write:(bytes + _writeOffset)
                                      maxLength:(len - _writeOffset)];
                  if (_debug)
                    {
                      NSWarnMLog(@"[OutputStream] => wrote %d bytes to output", written);
                    }

                  if (written > 0)
                    {
                      if (_debug == YES)
                        {
                          debugWrite(self, written, bytes + _writeOffset);
                        }
                      _writeOffset += written;
                      if (_writeOffset >= (int)len)
                        {
                          DESTROY(_writeData);

                          // Now we handle the body (if any)
                          if (_body == nil)
                            {
                              _body = RETAIN([this->request HTTPBodyStream]);
                              if (_body == nil)
                                {
                                  // No streaming => just use the raw [request HTTPBody]
                                  NSData *dBody = [this->request HTTPBody];
                                  if (dBody != nil)
                                    {
                                      _body = [NSInputStream alloc];
                                      _body = [_body initWithData:dBody];
                                      [_body open];
                                    }
                                  else
                                    {
                                      // No body at all => we are done sending
                                      sent = YES;
                                    }
                                }
                              else
                                {
                                  // We do have a streaming body => ensure it's open
                                  if (_debug)
                                    {
                                      NSWarnMLog(@"[OutputStream] => found an existing HTTPBodyStream => opening it now");
                                    }
                                  [_body open];
                                }
                            }
                        }
                    }
                }
              else if (_body != nil)
                {
                  // If we still have body data left
                  if ([_body hasBytesAvailable])
                    {
                      int len = [_body read:WRITE_BUFFER maxLength:MAX_WRITE_BUFFER];
                      if (_debug)
                        {
                          NSWarnMLog(@"[OutputStream] => read %d bytes from _body (streamStatus=%ld)",
                                     len, (long)[_body streamStatus]);
                        }
                      if (len < 0)
                        {
                          if (_debug)
                            {
                              NSWarnMLog(@"[OutputStream] => error reading from HTTPBody stream => stopping load");
                            }
                          [self stopLoading];
                          NSError *err = [NSError errorWithDomain:@"can't read body"
                                                             code:0
                                                         userInfo:nil];
                          [this->client URLProtocol:self didFailWithError:err];
                          DESTROY(this->client);
                          return;
                        }
                      else if (len > 0)
                        {
                          written = [this->output write:WRITE_BUFFER maxLength:len];
                          if (_debug)
                            {
                              NSWarnMLog(@"[OutputStream] => wrote %d body bytes to output", written);
                            }
                          if (written > 0)
                            {
                              if (_debug)
                                {
                                  debugWrite(self, written, WRITE_BUFFER);
                                }
                              len -= written;
                              if (len > 0)
                                {
                                  if (_debug)
                                    {
                                      NSWarnMLog(@"[OutputStream] => partial write => saving leftover data, %d bytes", len);
                                    }
                                  // We have leftover data => store in _writeData
                                  _writeData = [[NSData alloc] initWithBytes:(WRITE_BUFFER+written)
                                                                      length:len];
                                  _writeOffset = 0;
                                }
                              else if (len == 0 && ![_body hasBytesAvailable])
                                {
                                  // all body bytes are written => done
                                  [_body close];
                                  DESTROY(_body);
                                  sent = YES;
                                }
                            }
                          else if ([this->output streamStatus] == NSStreamStatusWriting)
                            {
                              if (_debug)
                                {
                                  NSWarnMLog(@"[OutputStream] => wrote 0 bytes => storing leftover of length=%d", len);
                                }
                              _writeData = [[NSData alloc] initWithBytes:WRITE_BUFFER
                                                                  length:len];
                              _writeOffset = 0;
                            }
                        }
                      else
                        {
                          // len == 0 => body has no more data => done
                          [_body close];
                          DESTROY(_body);
                          sent = YES;
                        }
                    }
                  else
                    {
                      // no more bytes in _body => done
                      [_body close];
                      DESTROY(_body);
                      sent = YES;
                    }
                }

              if (sent == YES)
                {
                  if (_debug)
                    {
                      NSWarnMLog(@"[OutputStream] => request fully sent => shouldClose=%ld", (long)_shouldClose);
                    }
                  if (_shouldClose == YES)
                    {
                      if (_debug)
                        {
                          NSWarnMLog(@"[OutputStream] => _shouldClose => removing from runloop, closing stream");
                        }
                      [this->output setDelegate:nil];
                      [this->output removeFromRunLoop:[NSRunLoop currentRunLoop]
                                             forMode:NSDefaultRunLoopMode];
                      [this->output close];
                      DESTROY(this->output);
                    }
                }

              if (_debug)
                {
                  NSWarnMLog(@"[OutputStream] => done handling hasSpaceAvailable => returning");
                }
              return;
            } // end case NSStreamEventHasSpaceAvailable

          default:
            // We'll handle unexpected events below or after the switch
            break;
        }
    }
  else
    {
      NSLog(@"[handleEvent] Unexpected stream (%p) that doesn't match input (%p) or output (%p)",
            stream, this->input, this->output);
    }

  // -----------------------------------------------------------------------
  // If we get here => either a default or an error event not already handled
  // -----------------------------------------------------------------------
  if (event == NSStreamEventErrorOccurred)
    {
      NSError *error = AUTORELEASE(RETAIN([stream streamError]));
      if (_debug)
        {
          NSWarnMLog(@"[handleEvent] => NSStreamEventErrorOccurred => %@", error);
        }
      [self stopLoading];
      [this->client URLProtocol:self didFailWithError:error];
      DESTROY(this->client);
    }
  else
    {
      if (_debug)
        {
          NSWarnMLog(@"[handleEvent] => ignoring unexpected event=0x%lx on stream=%p of self=%@",
                     (unsigned long)event, stream, self);
        }
      NSLog(@"[handleEvent] ignoring unexpected event=0x%lx on stream=%p of self=%@",
            (unsigned long)event, stream, self);
    }

  if (_debug)
    {
      NSWarnMLog(@"[MethodExit] stream=%p handleEvent=0x%lx => done", stream, (unsigned long)event);
    }
}


- (void) useCredential: (NSURLCredential*)credential
  forAuthenticationChallenge: (NSURLAuthenticationChallenge*)challenge
{
  if (challenge == _challenge)
    {
      ASSIGN(_credential, credential);
    }
}
@end

@implementation _NSHTTPSURLProtocol

+ (BOOL) canInitWithRequest: (NSURLRequest*)request
{
  return [[[request URL] scheme] isEqualToString: @"https"];
}

@end

@implementation _NSFTPURLProtocol

+ (BOOL) canInitWithRequest: (NSURLRequest*)request
{
  return [[[request URL] scheme] isEqualToString: @"ftp"];
}

+ (NSURLRequest*) canonicalRequestForRequest: (NSURLRequest*)request
{
  return request;
}

- (void) startLoading
{
  if (this->cachedResponse)
    { // handle from cache
    }
  else
    {
      NSURL	*url = [this->request URL];
      NSHost	*host = [NSHost hostWithName: [url host]];

      if (host == nil)
        {
	  host = [NSHost hostWithAddress: [url host]];
	}
      [NSStream getStreamsToHost: host
			    port: [[url port] intValue]
		     inputStream: &this->input
		    outputStream: &this->output];
      if (this->input == nil || this->output == nil)
	{
    NSError *error = [NSError errorWithDomain: @"can't connect" code: 0 userInfo: nil];
	  [this->client URLProtocol: self didFailWithError: error];
    DESTROY(this->client);
	  return;
	}
      [this->input retain];
      [this->output retain];
      if ([[url scheme] isEqualToString: @"https"] == YES)
        {
          [this->input setProperty: NSStreamSocketSecurityLevelNegotiatedSSL
                            forKey: NSStreamSocketSecurityLevelKey];
          [this->output setProperty: NSStreamSocketSecurityLevelNegotiatedSSL
                             forKey: NSStreamSocketSecurityLevelKey];
        }
      [this->input setDelegate: self];
      [this->output setDelegate: self];
      [this->input scheduleInRunLoop: [NSRunLoop currentRunLoop]
			     forMode: NSDefaultRunLoopMode];
      [this->output scheduleInRunLoop: [NSRunLoop currentRunLoop]
			      forMode: NSDefaultRunLoopMode];
      // set socket options for ftps requests
      [this->input open];
      [this->output open];
    }
}

- (void) stopLoading
{
  if (this->input)
    {
      [this->input setDelegate: nil];
      [this->output setDelegate: nil];
      [this->input removeFromRunLoop: [NSRunLoop currentRunLoop]
			     forMode: NSDefaultRunLoopMode];
      [this->output removeFromRunLoop: [NSRunLoop currentRunLoop]
			      forMode: NSDefaultRunLoopMode];
      [this->input close];
      [this->output close];
      DESTROY(this->input);
      DESTROY(this->output);
    }
}

- (void) stream: (NSStream *) stream handleEvent: (NSStreamEvent) event
{
  if (stream == this->input) 
    {
      switch(event)
	{
	  case NSStreamEventHasBytesAvailable: 
	    {
	    NSLog(@"FTP input stream has bytes available");
      // implement FTP protocol
      //[this->client URLProtocol: self didLoadData: [NSData dataWithBytes: buffer length: len]];	// notify
	    return;
	    }
	  case NSStreamEventEndEncountered: 	// can this occur in parallel to NSStreamEventHasBytesAvailable???
		  NSLog(@"FTP input stream did end");
		  [this->client URLProtocolDidFinishLoading: self];
      DESTROY(this->client);
		  return;
	  case NSStreamEventOpenCompleted: 
		  // prepare to receive header
		  NSLog(@"FTP input stream opened");
		  return;
	  default: 
		  break;
	}
    }
  else if (stream == this->output)
    {
      NSLog(@"An event occurred on the output stream.");
  	// if successfully opened, send out FTP request header
    }
  else
    {
      NSLog(@"Unexpected event %"PRIuPTR
	" occurred on stream %@ not being used by %@",
	event, stream, self);
    }
  if (event == NSStreamEventErrorOccurred)
    {
      NSLog(@"An error %@ occurred on stream %@ of %@",
            [stream streamError], stream, self);
      [self stopLoading];
      [this->client URLProtocol: self didFailWithError: [stream streamError]];
      DESTROY(this->client);
    }
  else
    {
      NSLog(@"Unexpected event %"PRIuPTR" ignored on stream %@ of %@",
	event, stream, self);
    }
}

@end

@implementation _NSFileURLProtocol

+ (BOOL) canInitWithRequest: (NSURLRequest*)request
{
  return [[[request URL] scheme] isEqualToString: @"file"];
}

+ (NSURLRequest*) canonicalRequestForRequest: (NSURLRequest*)request
{
  return request;
}

- (void) startLoading
{
  // check for GET/PUT/DELETE etc so that we can also write to a file
  NSData	*data;
  NSURLResponse	*r;

  data = [NSData dataWithContentsOfFile: [[this->request URL] path]
  /* options: error: - don't use that because it is based on self */];
  if (data == nil)
    {
      NSDictionary *errorinfo = [NSDictionary dictionaryWithObjectsAndKeys:
                                 [this->request URL], @"URL",
                                 [[this->request URL] path], @"path",
                                 nil];
      NSError      *error = [NSError errorWithDomain: @"can't load file" code: 0 userInfo: errorinfo];
      [this->client URLProtocol: self didFailWithError: error];
      DESTROY(this->client);
      return;
    }

  /* FIXME ... maybe should infer MIME type and encoding from extension or BOM
   */
  r = [[NSURLResponse alloc] initWithURL: [this->request URL]
				MIMEType: @"text/html"
		   expectedContentLength: [data length]
			textEncodingName: @"unknown"];	
  [this->client URLProtocol: self
    didReceiveResponse: r
    cacheStoragePolicy: NSURLRequestUseProtocolCachePolicy];
  [this->client URLProtocol: self didLoadData: data];
  [this->client URLProtocolDidFinishLoading: self];
  DESTROY(this->client);
  RELEASE(r);
}

- (void) stopLoading
{
  return;
}

@end

@implementation _NSDataURLProtocol

+ (BOOL) canInitWithRequest: (NSURLRequest*)request
{
  return [[[request URL] scheme] isEqualToString: @"data"];
}

+ (NSURLRequest*) canonicalRequestForRequest: (NSURLRequest*)request
{
  return request;
}

- (void) startLoading
{
  NSURLResponse *r;
  NSString      *mime = @"text/plain";
  NSString      *encoding = @"US-ASCII";
  NSData        *data;
  NSString      *spec = [[this->request URL] resourceSpecifier];
  NSRange       comma = [spec rangeOfString:@","];
  NSEnumerator  *types;
  NSString      *type;
  BOOL          base64 = NO;

  if (comma.location == NSNotFound)
    {
      NSDictionary      *ui;
      NSError           *error;

      ui = [NSDictionary dictionaryWithObjectsAndKeys:
        [this->request URL], @"URL",
        [[this->request URL] path], @"path",
        nil];
      error = [NSError errorWithDomain: @"can't load data"
                                  code: 0
                              userInfo: ui];
      [this->client URLProtocol: self didFailWithError: error];
      DESTROY(this->client);
      return;
    }
  types = [[[spec substringToIndex: comma.location]
    componentsSeparatedByString: @";"] objectEnumerator];
  while (nil != (type = [types nextObject]))
    {
      if ([type isEqualToString: @"base64"])
	{
	  base64 = YES;
	}
      else if ([type hasPrefix: @"charset="])
	{
	  encoding = [type substringFromIndex: 8];
	}
      else if ([type length] > 0)
	{
	  mime = type;
	}
    }
  spec = [spec substringFromIndex: comma.location + 1];
  if (YES == base64)
    {
      data = [GSMimeDocument decodeBase64:
        [spec dataUsingEncoding: NSUTF8StringEncoding]];
    }
  else
    {
      data = [[spec stringByReplacingPercentEscapesUsingEncoding:
        NSUTF8StringEncoding] dataUsingEncoding: NSUTF8StringEncoding];
    }
  r = [[NSURLResponse alloc] initWithURL: [this->request URL]
    MIMEType: mime
    expectedContentLength: [data length]
    textEncodingName: encoding];

  [this->client URLProtocol: self
         didReceiveResponse: r 
	 cacheStoragePolicy: NSURLRequestUseProtocolCachePolicy];
  [this->client URLProtocol: self didLoadData: data];
  [this->client URLProtocolDidFinishLoading: self];
  DESTROY(this->client);
  RELEASE(r);
}

- (void) stopLoading
{
  return;
}

@end

@implementation _NSAboutURLProtocol

+ (BOOL) canInitWithRequest: (NSURLRequest*)request
{
  return [[[request URL] scheme] isEqualToString: @"about"];
}

+ (NSURLRequest*) canonicalRequestForRequest: (NSURLRequest*)request
{
  return request;
}

- (void) startLoading
{
  NSURLResponse	*r;
  NSData	*data = [NSData data];	// no data

  // we could pass different content depending on the url path
  r = [[NSURLResponse alloc] initWithURL: [this->request URL]
				MIMEType: @"text/html"
		   expectedContentLength: 0
			textEncodingName: @"utf-8"];	
  [this->client URLProtocol: self
    didReceiveResponse: r
    cacheStoragePolicy: NSURLRequestUseProtocolCachePolicy];
  [this->client URLProtocol: self didLoadData: data];
  [this->client URLProtocolDidFinishLoading: self];
  DESTROY(this->client);
  RELEASE(r);
}

- (void) stopLoading
{
  return;
}

@end
