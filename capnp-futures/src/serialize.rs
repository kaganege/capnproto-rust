// Copyright (c) 2013-2016 Sandstorm Development Group, Inc. and contributors
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
//! [standard stream framing](https://capnproto.org/encoding.html#serialization-over-a-stream).
//!
//! Each message is preceded by a segment table indicating the size of its segments.

use alloc::string::ToString;
use capnp::serialize::{OwnedSegments, SegmentLengthsBuilder};
use capnp::{message, Error, ErrorKind, OutputSegments, Result};
use embedded_io_async::{ErrorType, Read, ReadExactError, Write};

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
        None => Err(Error::failed("Premature end of file".to_string())),
    }
}

/// Asynchronously reads a message from `reader`.
///
/// Returns `None` if `reader` has zero bytes left (i.e. is at end-of-file).
/// To read a stream containing an unknown number of messages, you could call
/// this function repeatedly until it returns `None`.
pub async fn try_read_message<R>(
    mut reader: R,
    options: message::ReaderOptions,
) -> Result<Option<message::Reader<OwnedSegments>>>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    let Some(segment_lengths_builder) = read_segment_table(&mut reader, options).await? else {
        return Ok(None);
    };
    Ok(Some(
        read_segments(
            reader,
            segment_lengths_builder.into_owned_segments(),
            options,
        )
        .await?,
    ))
}

async fn read_segment_table<R>(
    mut reader: R,
    options: message::ReaderOptions,
) -> Result<Option<SegmentLengthsBuilder>>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    let mut buf: [u8; 8] = [0; 8];
    {
        let n = reader.read(&mut buf[..]).await.map_err(Into::into)?;
        if n == 0 {
            return Ok(None);
        } else if n < 8 {
            reader
                .read_exact(&mut buf[n..])
                .await
                .map_err(|e| match e {
                    ReadExactError::UnexpectedEof => {
                        capnp::Error::from_kind(ErrorKind::PrematureEndOfFile)
                    }
                    ReadExactError::Other(e) => e.into(),
                })?;
        }
    }
    let (segment_count, first_segment_length) = parse_segment_table_first(&buf[..])?;

    let mut segment_lengths_builder = SegmentLengthsBuilder::with_capacity(segment_count);
    segment_lengths_builder.try_push_segment(first_segment_length)?;
    if segment_count > 1 {
        if segment_count < 4 {
            // small enough that we can reuse our existing buffer
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|_| capnp::Error::from_kind(ErrorKind::Failed))?;
            for idx in 0..(segment_count - 1) {
                let segment_len =
                    u32::from_le_bytes(buf[(idx * 4)..(idx + 1) * 4].try_into().unwrap()) as usize;
                segment_lengths_builder.try_push_segment(segment_len)?;
            }
        } else {
            let mut segment_sizes = vec![0u8; (segment_count & !1) * 4];
            reader
                .read_exact(&mut segment_sizes[..])
                .await
                .map_err(|_| capnp::Error::from_kind(ErrorKind::Failed))?;
            for idx in 0..(segment_count - 1) {
                let segment_len =
                    u32::from_le_bytes(segment_sizes[(idx * 4)..(idx + 1) * 4].try_into().unwrap())
                        as usize;
                segment_lengths_builder.try_push_segment(segment_len)?;
            }
        }
    }

    // Don't accept a message which the receiver couldn't possibly traverse without hitting the
    // traversal limit. Without this check, a malicious client could transmit a very large segment
    // size to make the receiver allocate excessive space and possibly crash.
    if let Some(traversal_limit_in_words) = options.traversal_limit_in_words {
        if segment_lengths_builder.total_words() > traversal_limit_in_words {
            return Err(Error::failed(format!(
                "Message has {} words, which is too large. To increase the limit on the \
                         receiving end, see capnp::message::ReaderOptions.",
                segment_lengths_builder.total_words()
            )));
        }
    }

    Ok(Some(segment_lengths_builder))
}

/// Reads segments from `read`.
async fn read_segments<R>(
    mut read: R,
    mut owned_segments: OwnedSegments,
    options: message::ReaderOptions,
) -> Result<message::Reader<OwnedSegments>>
where
    R: Read + Unpin,
    <R as ErrorType>::Error: Into<Error>,
{
    read.read_exact(&mut owned_segments[..])
        .await
        .map_err(|_| capnp::Error::from_kind(ErrorKind::Failed))?;
    Ok(message::Reader::new(owned_segments, options))
}

/// Parses the first word of the segment table.
///
/// The segment table format for streams is defined in the Cap'n Proto
/// [encoding spec](https://capnproto.org/encoding.html#serialization-over-a-stream)
///
/// Returns the segment count and first segment length, or a state if the
/// read would block.
fn parse_segment_table_first(buf: &[u8]) -> Result<(usize, usize)> {
    let segment_count = u32::from_le_bytes(buf[0..4].try_into().unwrap()).wrapping_add(1);
    if segment_count >= 512 {
        return Err(Error::failed(format!("Too many segments: {segment_count}")));
    } else if segment_count == 0 {
        return Err(Error::failed(format!("Too few segments: {segment_count}")));
    }

    let first_segment_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    Ok((segment_count as usize, first_segment_len as usize))
}

/// Something that contains segments ready to be written out.
pub trait AsOutputSegments {
    fn as_output_segments(&self) -> OutputSegments<'_>;
}

impl<M> AsOutputSegments for &M
where
    M: AsOutputSegments,
{
    fn as_output_segments(&self) -> OutputSegments<'_> {
        (*self).as_output_segments()
    }
}

impl<A> AsOutputSegments for message::Builder<A>
where
    A: message::Allocator,
{
    fn as_output_segments(&self) -> OutputSegments<'_> {
        self.get_segments_for_output()
    }
}

impl<A> AsOutputSegments for alloc::rc::Rc<message::Builder<A>>
where
    A: message::Allocator,
{
    fn as_output_segments(&self) -> OutputSegments<'_> {
        self.get_segments_for_output()
    }
}

impl<A> AsOutputSegments for alloc::sync::Arc<message::Builder<A>>
where
    A: message::Allocator,
{
    fn as_output_segments(&self) -> OutputSegments<'_> {
        self.get_segments_for_output()
    }
}

/// Writes the provided message to `writer`. Does not call `flush()`.
pub async fn write_message<W, M>(mut writer: W, message: M) -> Result<()>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
    M: AsOutputSegments,
{
    let segments = message.as_output_segments();
    write_segment_table(&mut writer, &segments[..]).await?;
    write_segments(writer, &segments[..]).await?;
    Ok(())
}

async fn write_segment_table<W>(mut write: W, segments: &[&[u8]]) -> Result<()>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
{
    let mut buf: [u8; 8] = [0; 8];
    let segment_count = segments.len();

    // write the first Word, which contains segment_count and the 1st segment length
    buf[0..4].copy_from_slice(&(segment_count as u32 - 1).to_le_bytes());
    buf[4..8].copy_from_slice(&((segments[0].len() / 8) as u32).to_le_bytes());
    write.write_all(&buf).await.map_err(Into::into)?;

    if segment_count > 1 {
        if segment_count < 4 {
            for idx in 1..segment_count {
                buf[(idx - 1) * 4..idx * 4]
                    .copy_from_slice(&((segments[idx].len() / 8) as u32).to_le_bytes());
            }
            if segment_count == 2 {
                for value in &mut buf[4..8] {
                    *value = 0;
                }
            }
            write.write_all(&buf).await.map_err(Into::into)?;
        } else {
            let mut buf = vec![0; (segment_count & !1) * 4];
            for idx in 1..segment_count {
                buf[(idx - 1) * 4..idx * 4]
                    .copy_from_slice(&((segments[idx].len() / 8) as u32).to_le_bytes());
            }
            if segment_count % 2 == 0 {
                for idx in (buf.len() - 4)..(buf.len()) {
                    buf[idx] = 0
                }
            }
            write.write_all(&buf).await.map_err(Into::into)?;
        }
    }
    Ok(())
}

/// Writes segments to `write`.
async fn write_segments<W>(mut write: W, segments: &[&[u8]]) -> Result<()>
where
    W: Write + Unpin,
    <W as ErrorType>::Error: Into<Error>,
{
    for segment in segments {
        write.write_all(segment).await.map_err(Into::into)?;
    }
    Ok(())
}

#[cfg(test)]
pub mod test {
    use embedded_io_adapters::futures_03::FromFutures;
    use embedded_io_adapters::std::FromStd;
    use futures::io::Cursor;

    use quickcheck::{quickcheck, TestResult};

    use capnp::message::ReaderSegments;
    use capnp::{message, Error, OutputSegments};

    use super::{read_segment_table, try_read_message, write_message, AsOutputSegments};

    #[test]
    fn test_read_segment_table() {
        let mut exec = futures::executor::LocalPool::new();
        let mut buf = vec![];

        buf.extend(
            [
                0, 0, 0, 0, // 1 segments
                0, 0, 0, 0,
            ], // 0 length
        );
        let segment_lengths = exec
            .run_until(read_segment_table(
                FromFutures::new(Cursor::new(&buf[..])),
                message::ReaderOptions::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(0, segment_lengths.total_words());
        assert_eq!(vec![(0, 0)], segment_lengths.to_segment_indices());
        buf.clear();

        buf.extend(
            [
                0, 0, 0, 0, // 1 segments
                1, 0, 0, 0,
            ], // 1 length
        );

        let segment_lengths = exec
            .run_until(read_segment_table(
                FromFutures::new(&mut Cursor::new(&buf[..])),
                message::ReaderOptions::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(1, segment_lengths.total_words());
        assert_eq!(vec![(0, 1)], segment_lengths.to_segment_indices());
        buf.clear();

        buf.extend(
            [
                1, 0, 0, 0, // 2 segments
                1, 0, 0, 0, // 1 length
                1, 0, 0, 0, // 1 length
                0, 0, 0, 0,
            ], // padding
        );
        let segment_lengths = exec
            .run_until(read_segment_table(
                FromFutures::new(&mut Cursor::new(&buf[..])),
                message::ReaderOptions::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(2, segment_lengths.total_words());
        assert_eq!(vec![(0, 1), (1, 2)], segment_lengths.to_segment_indices());
        buf.clear();

        buf.extend(
            [
                2, 0, 0, 0, // 3 segments
                1, 0, 0, 0, // 1 length
                1, 0, 0, 0, // 1 length
                0, 1, 0, 0,
            ], // 256 length
        );
        let segment_lengths = exec
            .run_until(read_segment_table(
                FromFutures::new(&mut Cursor::new(&buf[..])),
                message::ReaderOptions::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(258, segment_lengths.total_words());
        assert_eq!(
            vec![(0, 1), (1, 2), (2, 258)],
            segment_lengths.to_segment_indices()
        );
        buf.clear();

        buf.extend(
            [
                3, 0, 0, 0, // 4 segments
                77, 0, 0, 0, // 77 length
                23, 0, 0, 0, // 23 length
                1, 0, 0, 0, // 1 length
                99, 0, 0, 0, // 99 length
                0, 0, 0, 0,
            ], // padding
        );
        let segment_lengths = exec
            .run_until(read_segment_table(
                FromFutures::new(&mut Cursor::new(&buf[..])),
                message::ReaderOptions::new(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(200, segment_lengths.total_words());
        assert_eq!(
            vec![(0, 77), (77, 100), (100, 101), (101, 200)],
            segment_lengths.to_segment_indices()
        );
        buf.clear();
    }

    #[test]
    fn test_read_invalid_segment_table() {
        let mut exec = futures::executor::LocalPool::new();
        let mut buf = vec![];

        buf.extend([0, 2, 0, 0]); // 513 segments
        buf.extend([0; 513 * 4]);
        assert!(exec
            .run_until(read_segment_table(
                FromFutures::new(Cursor::new(&buf[..])),
                message::ReaderOptions::new()
            ))
            .is_err());
        buf.clear();

        buf.extend([0, 0, 0, 0]); // 1 segments
        assert!(exec
            .run_until(read_segment_table(
                FromFutures::new(Cursor::new(&buf[..])),
                message::ReaderOptions::new()
            ))
            .is_err());

        buf.clear();

        buf.extend([0, 0, 0, 0]); // 1 segments
        buf.extend([0; 3]);
        assert!(exec
            .run_until(read_segment_table(
                FromFutures::new(Cursor::new(&buf[..])),
                message::ReaderOptions::new()
            ))
            .is_err());
        buf.clear();

        buf.extend([255, 255, 255, 255]); // 0 segments
        assert!(exec
            .run_until(read_segment_table(
                FromFutures::new(Cursor::new(&buf[..])),
                message::ReaderOptions::new()
            ))
            .is_err());
        buf.clear();
    }

    fn construct_segment_table(segments: &[&[u8]]) -> Vec<u8> {
        let mut exec = futures::executor::LocalPool::new();
        let mut buf = vec![];
        exec.run_until(super::write_segment_table(&mut buf, segments))
            .unwrap();
        buf
    }

    #[test]
    fn test_construct_segment_table() {
        let segment_0: [u8; 0] = [];
        let segment_1 = [1, 0, 0, 0, 0, 0, 0, 0];
        let segment_199 = [197; 199 * 8];

        let buf = construct_segment_table(&[&segment_0]);
        assert_eq!(
            &[
                0, 0, 0, 0, // 1 segments
                0, 0, 0, 0
            ], // 0 length
            &buf[..]
        );

        let buf = construct_segment_table(&[&segment_1]);
        assert_eq!(
            &[
                0, 0, 0, 0, // 1 segments
                1, 0, 0, 0
            ], // 1 length
            &buf[..]
        );

        let buf = construct_segment_table(&[&segment_199]);
        assert_eq!(
            &[
                0, 0, 0, 0, // 1 segments
                199, 0, 0, 0
            ], // 199 length
            &buf[..]
        );

        let buf = construct_segment_table(&[&segment_0, &segment_1]);
        assert_eq!(
            &[
                1, 0, 0, 0, // 2 segments
                0, 0, 0, 0, // 0 length
                1, 0, 0, 0, // 1 length
                0, 0, 0, 0
            ], // padding
            &buf[..]
        );

        let buf = construct_segment_table(&[&segment_199, &segment_1, &segment_199, &segment_0]);
        assert_eq!(
            &[
                3, 0, 0, 0, // 4 segments
                199, 0, 0, 0, // 199 length
                1, 0, 0, 0, // 1 length
                199, 0, 0, 0, // 199 length
                0, 0, 0, 0, // 0 length
                0, 0, 0, 0
            ], // padding
            &buf[..]
        );

        let buf = construct_segment_table(&[
            &segment_199,
            &segment_1,
            &segment_199,
            &segment_0,
            &segment_1,
        ]);
        assert_eq!(
            &[
                4, 0, 0, 0, // 5 segments
                199, 0, 0, 0, // 199 length
                1, 0, 0, 0, // 1 length
                199, 0, 0, 0, // 199 length
                0, 0, 0, 0, // 0 length
                1, 0, 0, 0
            ], // 1 length
            &buf[..]
        );
    }

    impl AsOutputSegments for Vec<Vec<capnp::Word>> {
        fn as_output_segments(&self) -> OutputSegments<'_> {
            if self.is_empty() {
                OutputSegments::SingleSegment([&[]])
            } else if self.len() == 1 {
                OutputSegments::SingleSegment([capnp::Word::words_to_bytes(&self[0][..])])
            } else {
                OutputSegments::MultiSegment(
                    self.iter()
                        .map(|segment| capnp::Word::words_to_bytes(&segment[..]))
                        .collect::<Vec<_>>(),
                )
            }
        }
    }

    /// Wraps a `Read` instance and introduces blocking.
    pub(crate) struct BlockingRead<R>
    where
        R: embedded_io_async::Read,
    {
        /// The wrapped reader
        pub read: R,
    }

    impl<R> BlockingRead<R>
    where
        R: embedded_io_async::Read,
    {
        pub(crate) fn new(read: R) -> Self {
            Self { read }
        }
    }

    impl<R> embedded_io_async::ErrorType for BlockingRead<R>
    where
        R: embedded_io_async::Read + Unpin,
        <R as embedded_io_async::ErrorType>::Error: Into<Error>,
    {
        type Error = R::Error;
    }

    impl<R> embedded_io_async::Read for BlockingRead<R>
    where
        R: embedded_io_async::Read + Unpin,
        <R as embedded_io_async::ErrorType>::Error: Into<Error>,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.read.read(buf).await
        }
    }

    /// Wraps a `Write` instance and introduces blocking.
    pub(crate) struct BlockingWrite<W>
    where
        W: embedded_io_async::Write,
    {
        /// The wrapped writer
        writer: W,
    }

    impl<W> BlockingWrite<W>
    where
        W: embedded_io_async::Write,
    {
        pub(crate) fn new(writer: W) -> Self {
            Self { writer }
        }
        pub(crate) fn into_writer(self) -> W {
            self.writer
        }
    }

    impl<W> embedded_io_async::ErrorType for BlockingWrite<W>
    where
        W: embedded_io_async::Write + Unpin,
        <W as embedded_io_async::ErrorType>::Error: Into<Error>,
    {
        type Error = W::Error;
    }

    impl<W> embedded_io_async::Write for BlockingWrite<W>
    where
        W: embedded_io_async::Write + Unpin,
        <W as embedded_io_async::ErrorType>::Error: Into<Error>,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.writer.write(buf).await
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.writer.flush().await
        }

        async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
            self.writer.write_all(buf).await
        }
    }

    pub(crate) struct FromEmbeddedIo<T: ?Sized> {
        inner: T,
    }

    impl<T> FromEmbeddedIo<T> {
        pub fn new(inner: T) -> Self {
            Self { inner }
        }
    }

    impl<T: ?Sized> FromEmbeddedIo<T> {
        /// Mutably borrow the inner object.
        pub fn inner_mut(&mut self) -> &mut T {
            &mut self.inner
        }
    }

    impl<T> embedded_io_async::ErrorType for FromEmbeddedIo<T>
    where
        T: embedded_io::ErrorType,
    {
        type Error = T::Error;
    }

    impl<T> embedded_io_async::Read for FromEmbeddedIo<T>
    where
        T: embedded_io::Read,
    {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            self.inner.read(buf)
        }

        async fn read_exact(
            &mut self,
            buf: &mut [u8],
        ) -> Result<(), embedded_io::ReadExactError<Self::Error>> {
            self.inner.read_exact(buf)
        }
    }

    impl<T> embedded_io_async::Write for FromEmbeddedIo<T>
    where
        T: embedded_io::Write,
    {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.inner.write(buf)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            self.inner.flush()
        }

        async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
            self.inner.write_all(buf)
        }
    }

    #[cfg_attr(miri, ignore)] // Miri takes a long time with quickcheck
    #[test]
    fn check_round_trip_async() {
        fn round_trip(write_blocking_period: usize, segments: Vec<Vec<capnp::Word>>) -> TestResult {
            if segments.is_empty() || write_blocking_period == 0 {
                return TestResult::discard();
            }
            let (mut read, segments) = {
                let cursor = std::io::Cursor::new(Vec::new());
                let mut writer = BlockingWrite::new(FromEmbeddedIo::new(FromStd::new(cursor)));
                futures::executor::block_on(Box::pin(write_message(&mut writer, &segments)))
                    .expect("writing");

                let mut cursor = writer.into_writer();
                cursor.inner_mut().inner_mut().set_position(0);
                (BlockingRead::new(cursor), segments)
            };

            let message = futures::executor::block_on(Box::pin(try_read_message(
                &mut read,
                Default::default(),
            )))
            .expect("reading")
            .unwrap();
            let message_segments = message.into_segments();

            TestResult::from_bool(segments.iter().enumerate().all(|(i, segment)| {
                capnp::Word::words_to_bytes(&segment[..])
                    == message_segments.get_segment(i as u32).unwrap()
            }))
        }

        quickcheck(round_trip as fn(usize, Vec<Vec<capnp::Word>>) -> TestResult);
    }
}
