package lsifstore

import (
	"context"

	"github.com/keegancsmith/sqlf"
	"github.com/opentracing/opentracing-go/log"

	"github.com/sourcegraph/sourcegraph/internal/codeintel/codenav/shared"
	"github.com/sourcegraph/sourcegraph/internal/observation"
)

// GetDiagnostics returns the diagnostics for the documents that have the given path prefix. This method
// also returns the size of the complete result set to aid in pagination.
func (s *store) GetDiagnostics(ctx context.Context, bundleID int, prefix string, limit, offset int) (_ []shared.Diagnostic, _ int, err error) {
	ctx, trace, endObservation := s.operations.getDiagnostics.With(ctx, &err, observation.Args{LogFields: []log.Field{
		log.Int("bundleID", bundleID),
		log.String("prefix", prefix),
		log.Int("limit", limit),
		log.Int("offset", offset),
	}})
	defer endObservation(1, observation.Args{})

	documentData, err := s.scanDocumentData(s.db.Query(ctx, sqlf.Sprintf(
		diagnosticsQuery,
		bundleID,
		prefix+"%",
		bundleID,
		prefix+"%",
	)))
	if err != nil {
		return nil, 0, err
	}

	// TODO - need to handle SCIP payload
	trace.Log(log.Int("numDocuments", len(documentData)))

	totalCount := 0
	for _, documentData := range documentData {
		totalCount += len(documentData.Document.Diagnostics)
	}
	trace.Log(log.Int("totalCount", totalCount))

	diagnostics := make([]shared.Diagnostic, 0, limit)
	for _, documentData := range documentData {
		for _, diagnostic := range documentData.Document.Diagnostics {
			offset--

			if offset < 0 && len(diagnostics) < limit {
				diagnostics = append(diagnostics, shared.Diagnostic{
					DumpID:         bundleID,
					Path:           documentData.Path,
					DiagnosticData: diagnostic,
				})
			}
		}
	}

	return diagnostics, totalCount, nil
}

const diagnosticsQuery = `
(
	SELECT
		sd.id,
		sid.document_path,
		NULL AS data,
		NULL AS ranges,
		NULL AS hovers,
		NULL AS monikers,
		NULL AS packages,
		NULL AS diagnostics,
		sd.raw_scip_payload AS scip_document
	FROM codeintel_scip_index_documents sid
	JOIN codeintel_scip_documents sd ON sd.id = sid.document_id
	WHERE
		sid.upload_id = %s AND
		sid.document_path = %s
	LIMIT 1
) UNION (
	SELECT
		dump_id,
		path,
		data,
		NULL AS ranges,
		NULL AS hovers,
		NULL AS monikers,
		NULL AS packages,
		diagnostics
	FROM
		lsif_data_documents
	WHERE
		dump_id = %s AND
		path LIKE %s
	ORDER BY path
)
`
