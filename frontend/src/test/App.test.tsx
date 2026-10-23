import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import App from "../App";

afterEach(() => vi.unstubAllGlobals());

it("shows the sample input but does not claim it has been analyzed initially", () => {
  render(<App />);
  expect(screen.getByLabelText("Message content")).toHaveValue(
    "Your bank account will be blocked. Share your OTP now: https://bit.ly/example.",
  );
  expect(screen.getByText(/Paste a message and select/i)).toBeInTheDocument();
  expect(screen.queryByText("Screening results")).not.toBeInTheDocument();
});

it("shows an API error when the request cannot connect", async () => {
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "Analyze message" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/could not connect to ScamLens/i);
});
