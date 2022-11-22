/*
 * NEST: Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This module contains the NEST service routes
 * API version: 0.1.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

import (
	"github.com/gin-gonic/gin"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc gin.HandlerFunc
}
