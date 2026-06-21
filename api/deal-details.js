export default async function handler(req, res) {
  try {
    const { dealId } = req.query;

    if (!dealId) {
      return res.status(400).json({
        success: false,
        error: "Missing dealId",
      });
    }

    const pipedriveResponse = await fetch(
  `https://massiveit.pipedrive.com/api/v2/deals/${encodeURIComponent(dealId)}?api_token=${process.env.PIPEDRIVE_API_TOKEN}&custom_fields=7f9e8b0448207575faae34e9bd688786ae87fe34`
);

    const result = await pipedriveResponse.json();

    if (!pipedriveResponse.ok) {
      return res.status(pipedriveResponse.status).json({
        success: false,
        error: "Failed to fetch deal from Pipedrive",
        details: result,
      });
    }

    const deal = result?.data || {};
    const PROPOSAL_FIELD_KEY = "7f9e8b0448207575faae34e9bd688786ae87fe34";

    return res.status(200).json({
      success: true,
      dealId: deal.id,
      proposalUrl: deal[PROPOSAL_FIELD_KEY] || null,
      dealTitle: deal.title || null
    });
  } catch (error) {
    console.error("deal-details error:", error);

    return res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
}
