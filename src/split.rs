use crate::stream::TlsStream;

use rustls::{ConnectionCommon, SideData};
use std::{
    cell::UnsafeCell,
    io,
    ops::{Deref, DerefMut},
    rc::Rc,
};
use tokio_uring::{buf::{IoBuf, IoBufMut}, BufResult};

#[derive(Debug)]
pub struct ReadHalf<C> {
    pub(crate) inner: Rc<UnsafeCell<TlsStream<C>>>,
}

#[derive(Debug)]
pub struct WriteHalf<C> {
    pub(crate) inner: Rc<UnsafeCell<TlsStream<C>>>,
}

pub fn split<C, SD>(stream: TlsStream<C>) -> (ReadHalf<C>, WriteHalf<C>)
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let rc = Rc::new(UnsafeCell::new(stream));
    (
        ReadHalf {
            inner: rc.clone(),
        },
        WriteHalf { inner: rc },
    )
}

impl<C, SD: SideData + 'static> ReadHalf<C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        let inner = unsafe { &mut *self.inner.get() };
        inner.read(buf).await
    }
}

impl<C, SD: SideData + 'static> WriteHalf<C>
where
    C: DerefMut + Deref<Target = ConnectionCommon<SD>>,
{
    pub async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let inner = unsafe { &mut *self.inner.get() };
        inner.write(buf).await
    }

    pub async fn write_all<B: IoBuf>(&mut self, buf: B) -> BufResult<(), B> {
        let inner = unsafe { &mut *self.inner.get() };
        inner.write_all(buf).await
    }
}
