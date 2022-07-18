package main

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer = otel.Tracer("webapp")

type SpanWrap struct {
	orig trace.Span
}

func (w *SpanWrap) End(options ...trace.SpanEndOption) {
	w.orig.End(options...)
}

func (w *SpanWrap) SetAttributes(kv ...attribute.KeyValue) {
	w.orig.SetAttributes(kv...)
}

func startSpan(ctx context.Context, name string) (context.Context, SpanWrap) {
	ctx, origSpan := tracer.Start(ctx, "getCurrentUser")
	return ctx, SpanWrap{orig: origSpan}
}

func installTracerProvider(ctx context.Context) error {
	client := otlptracegrpc.NewClient(otlptracegrpc.WithInsecure())
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return err
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(newResource()),
	)
	otel.SetTracerProvider(tracerProvider)
	return nil
}

func newResource() *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String("isucon11p"),
		semconv.ServiceVersionKey.String("0.0.1"),
	)
}
