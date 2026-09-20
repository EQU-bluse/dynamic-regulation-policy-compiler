from fastapi import FastAPI


app = FastAPI(title="Dynamic Regulation Policy Compiler")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
