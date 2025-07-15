// Copyright (c) 2016 Sandstorm Development Group, Inc. and contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use capnp::{message, Error};
use embedded_io_async::{ErrorType, Read};

async fn read_next_message<R>(
    mut reader: R,
    options: message::ReaderOptions,
) -> Result<(R, Option<message::Reader<capnp::serialize::OwnedSegments>>), Error>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    let m = crate::serialize::try_read_message(&mut reader, options).await?;
    Ok((reader, m))
}

type ReadStreamResult<R> =
    Result<(R, Option<message::Reader<capnp::serialize::OwnedSegments>>), Error>;

/// An incoming sequence of messages.
#[must_use = "streams do nothing unless polled"]
pub struct ReadStream<'a, R>
where
    R: Read + Unpin,
{
    options: message::ReaderOptions,
    read: Pin<Box<dyn Future<Output = ReadStreamResult<R>> + 'a>>,
}

impl<R> Unpin for ReadStream<'_, R> where R: Read + Unpin {}

impl<'a, R> ReadStream<'a, R>
where
    R: Read + Unpin + 'a,
    <R as ErrorType>::Error: Into<Error>,
{
    pub fn new(reader: R, options: message::ReaderOptions) -> Self {
        ReadStream {
            read: Box::pin(read_next_message(reader, options)),
            options,
        }
    }

    pub async fn read(
        &mut self,
    ) -> Option<Result<message::Reader<capnp::serialize::OwnedSegments>, Error>> {
        let (r, m) = match self.read.as_mut().await {
            Ok(x) => x,
            Err(e) => return Some(Err(e)),
        };
        self.read = Box::pin(read_next_message(r, self.options));
        m.map(Ok)
    }
}
