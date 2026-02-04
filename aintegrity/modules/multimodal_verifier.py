"""
Multimodal Verification Engine v1.0

Handles verification of non-textual content including:
- Image-text semantic consistency (CLIP-based)
- Media integrity via perceptual hashing

Extracted from AIntegrity v4.0 Technical Specification.

Note: These modules require optional dependencies:
- VisualConsistencyVerifier: transformers, torch, PIL
- MediaIntegrityAssessor: PIL, imagehash
"""

from typing import Dict, Any, List, Optional, Union
import io
import hashlib


class VisualConsistencyVerifier:
    """
    Verifies semantic consistency between image and text content using CLIP.

    Version: 1.0

    This module uses CLIP (Contrastive Language-Image Pre-training) to
    generate embeddings for images and text, then calculates cosine similarity
    to assess consistency.

    High similarity = strong alignment
    Low similarity = potential contradiction, hallucination, or irrelevant pairing
    """

    def __init__(self, model_name: str = "openai/clip-vit-large-patch14"):
        """
        Initialize the visual consistency verifier.

        Args:
            model_name: HuggingFace model name for CLIP
        """
        self.model_name = model_name
        self.model = None
        self.processor = None
        self.device = "cpu"
        self._initialized = False

    def _lazy_init(self):
        """Lazily initialize the model (heavy dependencies)."""
        if self._initialized:
            return True

        try:
            import torch
            from transformers import CLIPProcessor, CLIPModel

            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.model = CLIPModel.from_pretrained(self.model_name).to(self.device)
            self.processor = CLIPProcessor.from_pretrained(self.model_name)
            self._initialized = True
            return True
        except ImportError as e:
            print(f"Warning: CLIP dependencies not available: {e}")
            return False

    def verify(
        self,
        image_data: Union[bytes, Any],
        text: str,
        threshold: float = 0.25
    ) -> Dict[str, Any]:
        """
        Calculate consistency score between image and text.

        Args:
            image_data: Image as bytes or PIL.Image
            text: Text description to verify against
            threshold: Minimum score for "consistent" classification

        Returns:
            Dictionary with consistency analysis results
        """
        if not self._lazy_init():
            return {
                "status": "UNAVAILABLE",
                "reason": "CLIP dependencies not installed. Install with: pip install transformers torch pillow"
            }

        try:
            from PIL import Image
            import torch

            # Handle image input
            if isinstance(image_data, bytes):
                image = Image.open(io.BytesIO(image_data))
            else:
                image = image_data  # Assume PIL Image

            # Process inputs
            inputs = self.processor(
                text=[text],
                images=image,
                return_tensors="pt",
                padding=True
            ).to(self.device)

            # Get similarity score
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits_per_image = outputs.logits_per_image
                # Normalize to 0-1 range
                similarity = logits_per_image.softmax(dim=1).item()

            return {
                "status": "COMPLETED",
                "consistency_score": similarity,
                "is_consistent": similarity >= threshold,
                "threshold": threshold,
                "model_used": self.model_name
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "reason": str(e)
            }

    def verify_batch(
        self,
        image_text_pairs: List[tuple],
        threshold: float = 0.25
    ) -> List[Dict[str, Any]]:
        """
        Verify multiple image-text pairs.

        Args:
            image_text_pairs: List of (image_data, text) tuples
            threshold: Minimum score for consistency

        Returns:
            List of verification results
        """
        return [self.verify(img, txt, threshold) for img, txt in image_text_pairs]


class MediaIntegrityAssessor:
    """
    Assesses the integrity of media files using perceptual hashing.

    Version: 1.0

    Unlike cryptographic hashes that change with any single-bit modification,
    perceptual hashes generate a "fingerprint" based on actual content,
    making them robust to:
    - Compression
    - Resizing
    - Format changes

    While still being sensitive to significant content modifications.
    """

    def __init__(self, hash_size: int = 8):
        """
        Initialize the media integrity assessor.

        Args:
            hash_size: Size of the perceptual hash (default 8 = 64 bits)
        """
        self.hash_size = hash_size
        self._imagehash_available = None

    def _check_dependencies(self) -> bool:
        """Check if required dependencies are available."""
        if self._imagehash_available is not None:
            return self._imagehash_available

        try:
            import imagehash
            from PIL import Image
            self._imagehash_available = True
        except ImportError:
            self._imagehash_available = False

        return self._imagehash_available

    def compute_phash(self, image_data: Union[bytes, Any]) -> Dict[str, Any]:
        """
        Compute perceptual hash for an image.

        Args:
            image_data: Image as bytes or PIL.Image

        Returns:
            Dictionary with hash and metadata
        """
        if not self._check_dependencies():
            return {
                "status": "UNAVAILABLE",
                "reason": "imagehash not installed. Install with: pip install imagehash pillow"
            }

        try:
            import imagehash
            from PIL import Image

            # Handle image input
            if isinstance(image_data, bytes):
                image = Image.open(io.BytesIO(image_data))
            else:
                image = image_data

            # Compute different hash types
            phash = str(imagehash.phash(image, hash_size=self.hash_size))
            ahash = str(imagehash.average_hash(image, hash_size=self.hash_size))
            dhash = str(imagehash.dhash(image, hash_size=self.hash_size))

            return {
                "status": "COMPLETED",
                "perceptual_hash": phash,
                "average_hash": ahash,
                "difference_hash": dhash,
                "hash_size": self.hash_size
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "reason": str(e)
            }

    def compare_images(
        self,
        image1: Union[bytes, Any],
        image2: Union[bytes, Any],
        threshold: int = 10
    ) -> Dict[str, Any]:
        """
        Compare two images for similarity using perceptual hashing.

        Args:
            image1: First image
            image2: Second image
            threshold: Maximum hash distance for "similar" classification

        Returns:
            Comparison results
        """
        if not self._check_dependencies():
            return {
                "status": "UNAVAILABLE",
                "reason": "imagehash not installed"
            }

        try:
            import imagehash
            from PIL import Image

            # Get images
            if isinstance(image1, bytes):
                img1 = Image.open(io.BytesIO(image1))
            else:
                img1 = image1

            if isinstance(image2, bytes):
                img2 = Image.open(io.BytesIO(image2))
            else:
                img2 = image2

            # Compute hashes
            hash1 = imagehash.phash(img1, hash_size=self.hash_size)
            hash2 = imagehash.phash(img2, hash_size=self.hash_size)

            # Calculate distance
            distance = hash1 - hash2

            return {
                "status": "COMPLETED",
                "hash1": str(hash1),
                "hash2": str(hash2),
                "hamming_distance": distance,
                "similarity_score": 1.0 - (distance / (self.hash_size ** 2)),
                "is_similar": distance <= threshold,
                "threshold": threshold
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "reason": str(e)
            }

    def compute_cryptographic_hash(self, data: bytes) -> Dict[str, str]:
        """
        Compute cryptographic hashes for exact integrity verification.

        Args:
            data: Binary data to hash

        Returns:
            Dictionary of hash algorithm -> hash value
        """
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest()
        }

    def assess(
        self,
        media_data: bytes,
        media_type: str = "image"
    ) -> Dict[str, Any]:
        """
        Comprehensive integrity assessment of media.

        Args:
            media_data: Binary media data
            media_type: Type of media ("image", "audio", "video")

        Returns:
            Assessment results including hashes
        """
        result: Dict[str, Any] = {
            "status": "COMPLETED",
            "media_type": media_type,
            "size_bytes": len(media_data),
            "cryptographic_hashes": self.compute_cryptographic_hash(media_data)
        }

        if media_type == "image":
            phash_result = self.compute_phash(media_data)
            if phash_result["status"] == "COMPLETED":
                result["perceptual_hashes"] = {
                    "phash": phash_result["perceptual_hash"],
                    "ahash": phash_result["average_hash"],
                    "dhash": phash_result["difference_hash"]
                }
            else:
                result["perceptual_hashes"] = None
                result["perceptual_hash_error"] = phash_result.get("reason")

        elif media_type in ("audio", "video"):
            result["perceptual_hashes"] = None
            result["note"] = f"{media_type} perceptual hashing not yet implemented"

        return result
