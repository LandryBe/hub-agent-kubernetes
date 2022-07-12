// Code generated by mocktail; DO NOT EDIT.

package edgeingress

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

// platformClientMock mock of PlatformClient.
type platformClientMock struct{ mock.Mock }

// newPlatformClientMock creates a new platformClientMock.
func newPlatformClientMock(tb testing.TB) *platformClientMock {
	tb.Helper()

	m := &platformClientMock{}
	m.Mock.Test(tb)

	tb.Cleanup(func() { m.AssertExpectations(tb) })

	return m
}

func (_m *platformClientMock) GetCertificate(_ context.Context) (Certificate, error) {
	_ret := _m.Called()

	_ra0, _ := _ret.Get(0).(Certificate)
	_rb1 := _ret.Error(1)

	return _ra0, _rb1
}

func (_m *platformClientMock) OnGetCertificate() *platformClientGetCertificateCall {
	return &platformClientGetCertificateCall{Call: _m.Mock.On("GetCertificate"), Parent: _m}
}

func (_m *platformClientMock) OnGetCertificateRaw() *platformClientGetCertificateCall {
	return &platformClientGetCertificateCall{Call: _m.Mock.On("GetCertificate"), Parent: _m}
}

type platformClientGetCertificateCall struct {
	*mock.Call
	Parent *platformClientMock
}

func (_c *platformClientGetCertificateCall) Panic(msg string) *platformClientGetCertificateCall {
	_c.Call = _c.Call.Panic(msg)
	return _c
}

func (_c *platformClientGetCertificateCall) Once() *platformClientGetCertificateCall {
	_c.Call = _c.Call.Once()
	return _c
}

func (_c *platformClientGetCertificateCall) Twice() *platformClientGetCertificateCall {
	_c.Call = _c.Call.Twice()
	return _c
}

func (_c *platformClientGetCertificateCall) Times(i int) *platformClientGetCertificateCall {
	_c.Call = _c.Call.Times(i)
	return _c
}

func (_c *platformClientGetCertificateCall) WaitUntil(w <-chan time.Time) *platformClientGetCertificateCall {
	_c.Call = _c.Call.WaitUntil(w)
	return _c
}

func (_c *platformClientGetCertificateCall) After(d time.Duration) *platformClientGetCertificateCall {
	_c.Call = _c.Call.After(d)
	return _c
}

func (_c *platformClientGetCertificateCall) Run(fn func(args mock.Arguments)) *platformClientGetCertificateCall {
	_c.Call = _c.Call.Run(fn)
	return _c
}

func (_c *platformClientGetCertificateCall) Maybe() *platformClientGetCertificateCall {
	_c.Call = _c.Call.Maybe()
	return _c
}

func (_c *platformClientGetCertificateCall) TypedReturns(a Certificate, b error) *platformClientGetCertificateCall {
	_c.Call = _c.Return(a, b)
	return _c
}

func (_c *platformClientGetCertificateCall) ReturnsFn(fn func() (Certificate, error)) *platformClientGetCertificateCall {
	_c.Call = _c.Return(fn)
	return _c
}

func (_c *platformClientGetCertificateCall) TypedRun(fn func()) *platformClientGetCertificateCall {
	_c.Call = _c.Call.Run(func(args mock.Arguments) {
		fn()
	})
	return _c
}

func (_c *platformClientGetCertificateCall) OnGetCertificate() *platformClientGetCertificateCall {
	return _c.Parent.OnGetCertificate()
}

func (_c *platformClientGetCertificateCall) OnGetCertificateByDomains(domains []string) *platformClientGetCertificateByDomainsCall {
	return _c.Parent.OnGetCertificateByDomains(domains)
}

func (_c *platformClientGetCertificateCall) OnGetEdgeIngresses() *platformClientGetEdgeIngressesCall {
	return _c.Parent.OnGetEdgeIngresses()
}

func (_c *platformClientGetCertificateCall) OnGetCertificateRaw() *platformClientGetCertificateCall {
	return _c.Parent.OnGetCertificateRaw()
}

func (_c *platformClientGetCertificateCall) OnGetCertificateByDomainsRaw(domains interface{}) *platformClientGetCertificateByDomainsCall {
	return _c.Parent.OnGetCertificateByDomainsRaw(domains)
}

func (_c *platformClientGetCertificateCall) OnGetEdgeIngressesRaw() *platformClientGetEdgeIngressesCall {
	return _c.Parent.OnGetEdgeIngressesRaw()
}

func (_m *platformClientMock) GetCertificateByDomains(_ context.Context, domains []string) (Certificate, error) {
	_ret := _m.Called(domains)

	if _rf, ok := _ret.Get(0).(func([]string) (Certificate, error)); ok {
		return _rf(domains)
	}

	_ra0, _ := _ret.Get(0).(Certificate)
	_rb1 := _ret.Error(1)

	return _ra0, _rb1
}

func (_m *platformClientMock) OnGetCertificateByDomains(domains []string) *platformClientGetCertificateByDomainsCall {
	return &platformClientGetCertificateByDomainsCall{Call: _m.Mock.On("GetCertificateByDomains", domains), Parent: _m}
}

func (_m *platformClientMock) OnGetCertificateByDomainsRaw(domains interface{}) *platformClientGetCertificateByDomainsCall {
	return &platformClientGetCertificateByDomainsCall{Call: _m.Mock.On("GetCertificateByDomains", domains), Parent: _m}
}

type platformClientGetCertificateByDomainsCall struct {
	*mock.Call
	Parent *platformClientMock
}

func (_c *platformClientGetCertificateByDomainsCall) Panic(msg string) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Panic(msg)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) Once() *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Once()
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) Twice() *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Twice()
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) Times(i int) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Times(i)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) WaitUntil(w <-chan time.Time) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.WaitUntil(w)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) After(d time.Duration) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.After(d)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) Run(fn func(args mock.Arguments)) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Run(fn)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) Maybe() *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Maybe()
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) TypedReturns(a Certificate, b error) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Return(a, b)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) ReturnsFn(fn func([]string) (Certificate, error)) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Return(fn)
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) TypedRun(fn func([]string)) *platformClientGetCertificateByDomainsCall {
	_c.Call = _c.Call.Run(func(args mock.Arguments) {
		_domains, _ := args.Get(0).([]string)
		fn(_domains)
	})
	return _c
}

func (_c *platformClientGetCertificateByDomainsCall) OnGetCertificate() *platformClientGetCertificateCall {
	return _c.Parent.OnGetCertificate()
}

func (_c *platformClientGetCertificateByDomainsCall) OnGetCertificateByDomains(domains []string) *platformClientGetCertificateByDomainsCall {
	return _c.Parent.OnGetCertificateByDomains(domains)
}

func (_c *platformClientGetCertificateByDomainsCall) OnGetEdgeIngresses() *platformClientGetEdgeIngressesCall {
	return _c.Parent.OnGetEdgeIngresses()
}

func (_c *platformClientGetCertificateByDomainsCall) OnGetCertificateRaw() *platformClientGetCertificateCall {
	return _c.Parent.OnGetCertificateRaw()
}

func (_c *platformClientGetCertificateByDomainsCall) OnGetCertificateByDomainsRaw(domains interface{}) *platformClientGetCertificateByDomainsCall {
	return _c.Parent.OnGetCertificateByDomainsRaw(domains)
}

func (_c *platformClientGetCertificateByDomainsCall) OnGetEdgeIngressesRaw() *platformClientGetEdgeIngressesCall {
	return _c.Parent.OnGetEdgeIngressesRaw()
}

func (_m *platformClientMock) GetEdgeIngresses(_ context.Context) ([]EdgeIngress, error) {
	_ret := _m.Called()

	_ra0, _ := _ret.Get(0).([]EdgeIngress)
	_rb1 := _ret.Error(1)

	return _ra0, _rb1
}

func (_m *platformClientMock) OnGetEdgeIngresses() *platformClientGetEdgeIngressesCall {
	return &platformClientGetEdgeIngressesCall{Call: _m.Mock.On("GetEdgeIngresses"), Parent: _m}
}

func (_m *platformClientMock) OnGetEdgeIngressesRaw() *platformClientGetEdgeIngressesCall {
	return &platformClientGetEdgeIngressesCall{Call: _m.Mock.On("GetEdgeIngresses"), Parent: _m}
}

type platformClientGetEdgeIngressesCall struct {
	*mock.Call
	Parent *platformClientMock
}

func (_c *platformClientGetEdgeIngressesCall) Panic(msg string) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Panic(msg)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) Once() *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Once()
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) Twice() *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Twice()
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) Times(i int) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Times(i)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) WaitUntil(w <-chan time.Time) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.WaitUntil(w)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) After(d time.Duration) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.After(d)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) Run(fn func(args mock.Arguments)) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Run(fn)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) Maybe() *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Maybe()
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) TypedReturns(a []EdgeIngress, b error) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Return(a, b)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) ReturnsFn(fn func() ([]EdgeIngress, error)) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Return(fn)
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) TypedRun(fn func()) *platformClientGetEdgeIngressesCall {
	_c.Call = _c.Call.Run(func(args mock.Arguments) {
		fn()
	})
	return _c
}

func (_c *platformClientGetEdgeIngressesCall) OnGetCertificate() *platformClientGetCertificateCall {
	return _c.Parent.OnGetCertificate()
}

func (_c *platformClientGetEdgeIngressesCall) OnGetCertificateByDomains(domains []string) *platformClientGetCertificateByDomainsCall {
	return _c.Parent.OnGetCertificateByDomains(domains)
}

func (_c *platformClientGetEdgeIngressesCall) OnGetEdgeIngresses() *platformClientGetEdgeIngressesCall {
	return _c.Parent.OnGetEdgeIngresses()
}

func (_c *platformClientGetEdgeIngressesCall) OnGetCertificateRaw() *platformClientGetCertificateCall {
	return _c.Parent.OnGetCertificateRaw()
}

func (_c *platformClientGetEdgeIngressesCall) OnGetCertificateByDomainsRaw(domains interface{}) *platformClientGetCertificateByDomainsCall {
	return _c.Parent.OnGetCertificateByDomainsRaw(domains)
}

func (_c *platformClientGetEdgeIngressesCall) OnGetEdgeIngressesRaw() *platformClientGetEdgeIngressesCall {
	return _c.Parent.OnGetEdgeIngressesRaw()
}
