"""
DataCompatibilityEngine — determines if a tool can run with available case data.
Returns GREEN / YELLOW / RED status with auto-populated QueryParameters.
"""
from typing import List
from ..core.models import (
    CompatibilityResult, CompatibilityStatus,
    QueryParameters, TargetData, ToolRequirements,
)


class DataCompatibilityEngine:
    """
    Validates case data against a tool's requirements.
    Builds QueryParameters automatically from TargetData with highest confidence.
    """

    def check(
        self,
        requirements: ToolRequirements,
        case_data: List[TargetData],
        extra_args: str = ""
    ) -> CompatibilityResult:
        # Build params from available data
        auto_params = QueryParameters.from_target_data(case_data, extra_args=extra_args)

        # Map field name → has value
        param_dict = auto_params.to_dict()
        available = [
            f for f in (requirements.mandatory + requirements.optional)
            if param_dict.get(f, "") not in ("", [], None)
        ]

        missing_mandatory = [
            f for f in requirements.mandatory
            if param_dict.get(f, "") in ("", [], None)
        ]
        missing_optional = [
            f for f in requirements.optional
            if param_dict.get(f, "") in ("", [], None)
        ]

        # Determine status
        if missing_mandatory:
            status = CompatibilityStatus.RED
        elif missing_optional:
            status = CompatibilityStatus.YELLOW
        else:
            status = CompatibilityStatus.GREEN

        # Build per-field hints for missing mandatory
        missing_hints = {
            f: hint for f, hint in requirements.how_to_get().items()
            if f in missing_mandatory or f in missing_optional
        }

        return CompatibilityResult(
            status=status,
            available=available,
            missing_mandatory=missing_mandatory,
            missing_optional=missing_optional,
            auto_params=auto_params,
            hint=requirements.hint,
            missing_hints=missing_hints,
        )

    def check_tool(self, tool, case_data: List[TargetData], extra_args: str = "") -> CompatibilityResult:
        """Convenience method: pass an OSINTTool directly."""
        if not tool.is_available:
            return CompatibilityResult(
                status=CompatibilityStatus.RED,
                available=[],
                missing_mandatory=[],
                missing_optional=[],
                hint=f"{tool.name} no está instalada o el servicio no está activo.",
                missing_hints={},
            )
        return self.check(tool.requirements, case_data, extra_args)
