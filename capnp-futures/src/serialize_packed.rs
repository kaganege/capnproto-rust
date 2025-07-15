// Copyright (c) 2013-2015 Sandstorm Development Group, Inc. and contributors
// Licensed under the MIT License:
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

//! Asynchronous reading and writing of messages using the
//! [packed stream encoding](https://capnproto.org/encoding.html#packing).

use alloc::string::ToString;
use core::pin::Pin;
use core::task::{Context, Poll};

use capnp::serialize::OwnedSegments;
use capnp::{message, Error, Result};
use embedded_io_async::{ErrorType, Read, Write};

use crate::serialize::AsOutputSegments;

enum PackedReadStage {
    Start,
    WritingZeroes,
    BufferingWord,
    DrainingBuffer,
    WritingPassthrough,
}

/// An `Read` wrapper that unpacks packed data.
pub struct PackedRead<R>
where
    R: Read + Unpin,
{
    inner: R,
    stage: PackedReadStage,

    // 10 = tag byte, up to 8 word bytes, and possibly one pass-through count
    buf: [u8; 10],

    buf_pos: usize,

    // number of bytes that we actually want to read into the buffer
    buf_size: usize,

    num_run_bytes_remaining: usize,
}

impl<R> PackedRead<R>
where
    R: Read + Unpin,
{
    /// Creates a new `PackedRead` from a `Read`. For optimal performance,
    /// `inner` should be a buffered `Read`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            stage: PackedReadStage::Start,
            buf: [0; 10],
            buf_pos: 0,
            buf_size: 10,
            num_run_bytes_remaining: 0,
        }
    }
}

impl<R> ErrorType for PackedRead<R>
where
    R: Read + Unpin,
{
    type Error = Error;
}

impl<R> Read for PackedRead<R>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    async fn read(&mut self, outbuf: &mut [u8]) -> core::result::Result<usize, Self::Error> {
        let Self {
            stage,
            inner,
            buf,
            buf_pos,
            num_run_bytes_remaining,
            buf_size,
            ..
        } = &mut *self;
        loop {
            match *stage {
                PackedReadStage::Start => {
                    let n = Pin::new(&mut *inner)
                        .read(&mut buf[*buf_pos..2])
                        .await
                        .map_err(Into::into)?;

                    if n == 0 {
                        return Ok(0);
                    }
                    *buf_pos += n;
                    if *buf_pos >= 2 {
                        let tag = buf[0];
                        let count = buf[1];
                        if tag == 0 {
                            *stage = PackedReadStage::WritingZeroes;
                            *num_run_bytes_remaining = (count as usize + 1) * 8;
                        } else {
                            *stage = PackedReadStage::BufferingWord;
                            *buf_size = buf[0].count_ones() as usize + 1;
                            if *buf_size == 9 {
                                // add a byte for the count of pass-through words
                                *buf_size = 10
                            }
                            if *buf_pos >= *buf_size {
                                // Skip the BufferingWord stage, because
                                // there is nothing left to buffer.
                                *stage = PackedReadStage::DrainingBuffer;
                                *buf_pos = 1;
                            }
                        }
                    }
                }
                PackedReadStage::WritingZeroes => {
                    let num_zeroes = core::cmp::min(outbuf.len(), *num_run_bytes_remaining);

                    for value in outbuf.iter_mut().take(num_zeroes) {
                        *value = 0;
                    }
                    if num_zeroes >= *num_run_bytes_remaining {
                        *buf_pos = 0;
                        *stage = PackedReadStage::Start;
                    } else {
                        *num_run_bytes_remaining -= num_zeroes;
                    }
                    return Ok(num_zeroes);
                }
                PackedReadStage::BufferingWord => {
                    match Pin::new(&mut *inner)
                        .read(&mut buf[*buf_pos..*buf_size])
                        .await
                        .map_err(Into::into)?
                    {
                        0 => {
                            return Err(Error::from_kind(
                                capnp::ErrorKind::PrematureEndOfPackedInput,
                            ))
                        }
                        n => {
                            *buf_pos += n;
                            if *buf_pos >= *buf_size {
                                *stage = PackedReadStage::DrainingBuffer;
                                *buf_pos = 1;
                            }
                        }
                    }
                }
                PackedReadStage::DrainingBuffer => {
                    let mut ii = 0;
                    let mut bitnum = *buf_pos - 1;
                    while ii < outbuf.len() && bitnum < 8 {
                        let is_nonzero = (buf[0] & (1u8 << bitnum)) != 0;
                        outbuf[ii] = buf[*buf_pos] & ((-i8::from(is_nonzero)) as u8);
                        ii += 1;
                        *buf_pos += usize::from(is_nonzero);
                        bitnum += 1;
                    }
                    if bitnum == 8 {
                        // We finished the word.
                        if *buf_pos == *buf_size {
                            // There are no passthrough words.
                            *stage = PackedReadStage::Start;
                        } else {
                            // We need to read some passthrough words.
                            *num_run_bytes_remaining = (buf[*buf_pos] as usize) * 8;
                            *stage = PackedReadStage::WritingPassthrough;
                        }
                        *buf_pos = 0;
                    } else {
                        // We did not finish the word.
                    }
                    return Ok(ii);
                }
                PackedReadStage::WritingPassthrough => {
                    let upper_bound = core::cmp::min(*num_run_bytes_remaining, outbuf.len());
                    if upper_bound == 0 {
                        *stage = PackedReadStage::Start;
                    } else {
                        let n = Pin::new(&mut *inner)
                            .read(&mut outbuf[0..upper_bound])
                            .await
                            .map_err(Into::into)?;

                        if n == 0 {
                            return Ok(0);
                        }
                        if n >= *num_run_bytes_remaining {
                            *stage = PackedReadStage::Start;
                        }
                        *num_run_bytes_remaining -= n;
                        return Ok(n);
                    }
                }
            }
        }
    }
}

/// Asynchronously reads a packed message from `read`.
///
/// Returns `None` if `read` has zero bytes left (i.e. is at end-of-file).
/// To read a stream containing an unknown number of messages, you could call
/// this function repeatedly until it returns `None`.
pub async fn try_read_message<R>(
    read: R,
    options: message::ReaderOptions,
) -> Result<Option<message::Reader<OwnedSegments>>>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    let packed_read = PackedRead::new(read);
    crate::serialize::try_read_message(packed_read, options).await
}

/// Asynchronously reads a message from `reader`.
pub async fn read_message<R>(
    reader: R,
    options: message::ReaderOptions,
) -> Result<message::Reader<OwnedSegments>>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    match try_read_message(reader, options).await? {
        Some(s) => Ok(s),
        None => Err(capnp::Error::failed("Premature end of file".to_string())),
    }
}

#[derive(PartialEq, Debug)]
enum PackedWriteStage {
    Start,
    WriteWord,
    WriteRunWordCount,
    WriteUncompressedRun,
}

/// An `Write` wrapper that packs any data passed into it.
pub struct PackedWrite<W>
where
    W: Write + Unpin,
{
    inner: W,
    stage: PackedWriteStage,
    buf: [u8; 8],
    buf_pos: usize,

    // tag and packed word
    packed_buf: [u8; 9],
    packed_buf_size: usize,

    run_bytes_remaining: usize,
}

struct FinishPendingWrites<W>
where
    W: Write + Unpin,
{
    inner: PackedWrite<W>,
}

impl<W> FinishPendingWrites<W>
where
    W: Write + Unpin,
{
    fn new(inner: PackedWrite<W>) -> Self {
        Self { inner }
    }
}

impl<W> core::future::Future for FinishPendingWrites<W>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
{
    type Output = core::result::Result<(), capnp::Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut fut = self.inner.finish_pending_writes();
        // SAFETY: we don't move the future after this line.
        let fut = unsafe { Pin::new_unchecked(&mut fut) };

        match fut.poll(cx)? {
            Poll::Ready(()) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Writes the provided message to `writer`. Does not call `writer.flush()`,
/// so that multiple successive calls can amortize work when `writer` is
/// buffered.
pub async fn write_message<W, M>(writer: W, message: M) -> Result<()>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
    M: AsOutputSegments,
{
    let mut packed_write = PackedWrite::new(writer);
    crate::serialize::write_message(&mut packed_write, message).await?;

    // Finish any pending work, so that nothing gets lost when we drop
    // the `PackedWrite`.
    FinishPendingWrites::new(packed_write).await
}

impl<W> PackedWrite<W>
where
    W: Write + Unpin,
{
    /// Creates a new `PackedWrite` from a `Write`. For optimal performance,
    /// `inner` should be a buffered `Write`.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            stage: PackedWriteStage::Start,
            buf: [0; 8],
            buf_pos: 0,
            packed_buf: [0; 9],
            packed_buf_size: 0,
            run_bytes_remaining: 0,
        }
    }
}

impl<W> PackedWrite<W>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
{
    async fn write_aux(&mut self, mut inbuf: &[u8]) -> Result<usize> {
        let mut inbuf_bytes_consumed: usize = 0;
        let Self {
            stage,
            inner,
            buf,
            buf_pos,
            packed_buf,
            packed_buf_size,
            run_bytes_remaining,
        } = self;
        loop {
            match *stage {
                PackedWriteStage::Start => {
                    if inbuf.is_empty() {
                        return Ok(inbuf_bytes_consumed);
                    }

                    // copy inbuf into buf
                    let buf_bytes_remaining = 8 - *buf_pos;
                    let bytes_to_copy = core::cmp::min(buf_bytes_remaining, inbuf.len());
                    buf[*buf_pos..(*buf_pos + bytes_to_copy)]
                        .copy_from_slice(&inbuf[..bytes_to_copy]);
                    inbuf = &inbuf[bytes_to_copy..];
                    inbuf_bytes_consumed += bytes_to_copy;
                    *buf_pos += bytes_to_copy;

                    if *buf_pos == 8 {
                        // compute tag
                        packed_buf[0] = 0;
                        let mut packed_buf_idx: usize = 1;
                        for (ii, b) in buf.iter().enumerate() {
                            if *b != 0 {
                                packed_buf[0] |= 1 << ii;
                                packed_buf[packed_buf_idx] = *b;
                                packed_buf_idx += 1;
                            }
                        }
                        *buf_pos = 0;
                        *packed_buf_size = packed_buf_idx;
                        *stage = PackedWriteStage::WriteWord;
                    }
                }
                PackedWriteStage::WriteWord => {
                    let n = Pin::new(&mut *inner)
                        .write(&packed_buf[*buf_pos..*packed_buf_size])
                        .await
                        .map_err(Into::into)?;

                    if inbuf_bytes_consumed > 0 {
                        return Ok(inbuf_bytes_consumed);
                    }

                    *buf_pos += n;

                    if *buf_pos == *packed_buf_size {
                        if packed_buf[0] == 0 {
                            // see how long of a run we can make
                            let mut words_in_run = inbuf.len() / 8;
                            for (idx, inb) in inbuf.iter().enumerate() {
                                if *inb != 0 {
                                    words_in_run = idx / 8;
                                    break;
                                }
                            }
                            *run_bytes_remaining = words_in_run * 8;
                            *stage = PackedWriteStage::WriteRunWordCount;
                        } else if packed_buf[0] == 255 {
                            // See how long of a run we can make.
                            // We look for at least two zeros because that's the point
                            // where our compression scheme becomes a net win.
                            let mut words_in_run = inbuf.len() / 8;

                            let mut zero_bytes_in_word = 0;
                            for (idx, inb) in inbuf.iter().enumerate() {
                                if idx % 8 == 0 {
                                    zero_bytes_in_word = 0;
                                }
                                if *inb == 0 {
                                    zero_bytes_in_word += 1;
                                    if zero_bytes_in_word > 1 {
                                        words_in_run = idx / 8;
                                        break;
                                    }
                                }
                            }
                            *run_bytes_remaining = words_in_run * 8;
                            *stage = PackedWriteStage::WriteRunWordCount;
                        } else {
                            *buf_pos = 0;
                            *stage = PackedWriteStage::Start;
                        }
                    }
                }
                PackedWriteStage::WriteRunWordCount => {
                    let n = Pin::new(&mut *inner)
                        .write(&[(*run_bytes_remaining / 8) as u8])
                        .await
                        .map_err(Into::into)?;

                    if inbuf_bytes_consumed > 0 {
                        return Ok(inbuf_bytes_consumed);
                    }

                    if n == 1 {
                        if packed_buf[0] == 0 {
                            // we're done here
                            inbuf = &inbuf[(*run_bytes_remaining)..];
                            inbuf_bytes_consumed += *run_bytes_remaining;
                            *buf_pos = 0;
                            *stage = PackedWriteStage::Start;
                        } else {
                            // need to forward the uncompressed words
                            *stage = PackedWriteStage::WriteUncompressedRun;
                        }
                    } else if n != 0 {
                        panic!("should not be possible");
                    }
                }

                PackedWriteStage::WriteUncompressedRun => {
                    let n = Pin::new(&mut *inner)
                        .write(&inbuf[..*run_bytes_remaining])
                        .await
                        .map_err(Into::into)?;

                    if inbuf_bytes_consumed > 0 {
                        return Ok(inbuf_bytes_consumed);
                    }

                    inbuf_bytes_consumed += n;
                    inbuf = &inbuf[n..];
                    if n < *run_bytes_remaining {
                        *run_bytes_remaining -= n;
                    } else {
                        *buf_pos = 0;
                        *stage = PackedWriteStage::Start;
                    }
                }
            }
        }
    }

    /// Finish any work that we can do without any new bytes.
    async fn finish_pending_writes(&mut self) -> Result<()> {
        while self.stage == PackedWriteStage::WriteWord
            || self.stage == PackedWriteStage::WriteRunWordCount
        {
            self.write_aux(&[]).await?;
        }
        Ok(())
    }
}

impl<W> embedded_io_async::ErrorType for PackedWrite<W>
where
    W: Write + Unpin,
{
    type Error = Error;
}

impl<W> Write for PackedWrite<W>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
{
    async fn write(&mut self, inbuf: &[u8]) -> core::result::Result<usize, Self::Error> {
        (*self).write_aux(inbuf).await
    }

    async fn flush(&mut self) -> core::result::Result<(), Self::Error> {
        (*self).finish_pending_writes().await?;

        Pin::new(&mut self.inner).flush().await.map_err(Into::into)
    }
}

#[cfg(test)]
pub mod test {
    use std::{boxed::Box, vec, vec::Vec};

    use crate::serialize::test::{BlockingRead, BlockingWrite, FromEmbeddedIo};
    use crate::serialize_packed::{try_read_message, PackedRead, PackedWrite};
    use capnp::message::ReaderSegments;
    use embedded_io_adapters::std::FromStd;
    use embedded_io_async::{Read, Write};
    use quickcheck::{quickcheck, TestResult};

    pub fn check_unpacks_to(packed: &[u8], unpacked: &[u8]) {
        let mut packed_read = PackedRead::new(crate::serialize::test::BlockingRead::new(packed));

        let mut bytes: Vec<u8> = vec![0; unpacked.len()];
        futures::executor::block_on(Box::pin(packed_read.read_exact(&mut bytes))).expect("reading");

        assert!(packed_read.inner.read.is_empty()); // nothing left to read
        assert_eq!(bytes, unpacked);
    }

    pub fn check_packing_with_periods(unpacked: &[u8], packed: &[u8]) {
        // --------
        // write

        let mut bytes: Vec<u8> = vec![0; packed.len()];
        {
            let mut packed_write =
                PackedWrite::new(crate::serialize::test::BlockingWrite::new(&mut bytes[..]));
            futures::executor::block_on(Box::pin(packed_write.write_all(unpacked)))
                .expect("writing");
            futures::executor::block_on(Box::pin(packed_write.flush())).expect("flushing");
        }

        assert_eq!(bytes, packed);

        // --------
        // read
        check_unpacks_to(packed, unpacked);
    }

    pub fn check_packing(unpacked: &[u8], packed: &[u8]) {
        // for ii in 1..10 {
        // for jj in 1..10 {
        check_packing_with_periods(unpacked, packed);
        // }
        // }
    }

    #[test]
    pub fn simple_packing() {
        check_packing(&[], &[]);
        check_packing(&[0; 8], &[0, 0]);
        check_packing(&[0, 0, 12, 0, 0, 34, 0, 0], &[0x24, 12, 34]);
        check_packing(
            &[1, 3, 2, 4, 5, 7, 6, 8],
            &[0xff, 1, 3, 2, 4, 5, 7, 6, 8, 0],
        );
        check_packing(
            &[0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 2, 4, 5, 7, 6, 8],
            &[0, 0, 0xff, 1, 3, 2, 4, 5, 7, 6, 8, 0],
        );
        check_packing(
            &[0, 0, 12, 0, 0, 34, 0, 0, 1, 3, 2, 4, 5, 7, 6, 8],
            &[0x24, 12, 34, 0xff, 1, 3, 2, 4, 5, 7, 6, 8, 0],
        );

        check_packing(
            &[1, 3, 2, 4, 5, 7, 6, 8, 8, 6, 7, 4, 5, 2, 3, 1],
            &[0xff, 1, 3, 2, 4, 5, 7, 6, 8, 1, 8, 6, 7, 4, 5, 2, 3, 1],
        );
        check_packing(
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                5, 6, 7, 8, 0, 2, 4, 0, 9, 0, 5, 1,
            ],
            &[
                0xff, 1, 2, 3, 4, 5, 6, 7, 8, 3, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1,
                2, 3, 4, 5, 6, 7, 8, 0xd6, 2, 4, 9, 5, 1,
            ],
        );

        check_packing(
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 6, 2, 4, 3, 9, 0, 5, 1, 1, 2, 3, 4,
                5, 6, 7, 8, 0, 2, 4, 0, 9, 0, 5, 1,
            ],
            &[
                0xff, 1, 2, 3, 4, 5, 6, 7, 8, 3, 1, 2, 3, 4, 5, 6, 7, 8, 6, 2, 4, 3, 9, 0, 5, 1, 1,
                2, 3, 4, 5, 6, 7, 8, 0xd6, 2, 4, 9, 5, 1,
            ],
        );

        check_packing(
            &[
                8, 0, 100, 6, 0, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 1,
            ],
            &[0xed, 8, 100, 6, 1, 1, 2, 0, 2, 0xd4, 1, 2, 3, 1],
        );
        check_packing(&[0; 16], &[0, 1]);
        check_packing(
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            &[0, 2],
        );
    }

    fn round_trip(
        read_blocking_period: usize,
        write_blocking_period: usize,
        segments: Vec<Vec<capnp::Word>>,
    ) -> TestResult {
        if segments.is_empty() || read_blocking_period == 0 || write_blocking_period == 0 {
            return TestResult::discard();
        }
        let (mut read, segments) = {
            let cursor = std::io::Cursor::new(Vec::new());
            let mut writer = BlockingWrite::new(FromEmbeddedIo::new(FromStd::new(cursor)));
            futures::executor::block_on(Box::pin(crate::serialize_packed::write_message(
                &mut writer,
                &segments,
            )))
            .expect("writing");
            futures::executor::block_on(Box::pin(writer.flush())).expect("writing");

            let mut cursor = writer.into_writer();
            cursor.inner_mut().inner_mut().set_position(0);
            (BlockingRead::new(cursor), segments)
        };

        let message = futures::executor::block_on(Box::pin(
            crate::serialize_packed::try_read_message(&mut read, Default::default()),
        ))
        .expect("reading")
        .unwrap();
        let message_segments = message.into_segments();

        TestResult::from_bool(segments.iter().enumerate().all(|(i, segment)| {
            capnp::Word::words_to_bytes(&segment[..])
                == message_segments.get_segment(i as u32).unwrap()
        }))
    }

    #[test]
    fn check_packed_round_trip_async_bug() {
        assert!(!round_trip(
            1,
            1,
            vec![vec![
                capnp::word(8, 14, 90, 7, 21, 13, 59, 17),
                capnp::word(0, 31, 21, 73, 0, 54, 61, 12)
            ]]
        )
        .is_failure());
    }

    #[cfg_attr(miri, ignore)]
    #[test]
    fn check_packed_round_trip_async() {
        quickcheck(round_trip as fn(usize, usize, Vec<Vec<capnp::Word>>) -> TestResult);
    }

    #[test]
    fn read_empty() {
        let words = [];
        // Before https://github.com/capnproto/capnproto-rust/pull/446
        // this would loop forever.
        let message =
            futures::executor::block_on(Box::pin(try_read_message(&words[..], Default::default())))
                .expect("reading");
        assert!(message.is_none());
    }

    #[test]
    fn eof_mid_message() {
        let words = [0xfe, 0x3, 0x3];
        let result =
            futures::executor::block_on(Box::pin(try_read_message(&words[..], Default::default())));

        match result {
            Ok(_) => panic!("expected error"),
            Err(e) => assert_eq!(e.kind, capnp::ErrorKind::PrematureEndOfFile),
        }
    }
}
